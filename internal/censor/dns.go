package censor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

type answer struct {
	RCode dnsmessage.RCode
	IPs   []string
}

func buildQuery(id uint16, name string, qtype dnsmessage.Type) ([]byte, error) {
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	qn, err := dnsmessage.NewName(name)
	if err != nil {
		return nil, err
	}
	m := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: qn, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	return m.Pack()
}

var errMismatch = errors.New("response does not match the query")

func parseAnswer(msg []byte, id uint16, qtype dnsmessage.Type) (answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return answer{}, err
	}
	if !h.Response || h.ID != id {
		return answer{}, errMismatch
	}
	if err := p.SkipAllQuestions(); err != nil {
		return answer{}, err
	}
	a := answer{RCode: h.RCode}
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return a, err
		}
		switch {
		case rh.Type == dnsmessage.TypeA && qtype == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return a, err
			}
			a.IPs = append(a.IPs, netip.AddrFrom4(r.A).String())
		case rh.Type == dnsmessage.TypeAAAA && qtype == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return a, err
			}
			a.IPs = append(a.IPs, netip.AddrFrom16(r.AAAA).String())
		default:
			if err := p.SkipAnswer(); err != nil {
				return a, err
			}
		}
	}
	return a, nil
}

func randomID() uint16 {
	var b [2]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint16(b[:])
}

func (r *runner) qtype() dnsmessage.Type {
	if r.n.Options().Family == netx.IPv6 {
		return dnsmessage.TypeAAAA
	}
	return dnsmessage.TypeA
}

func (r *runner) queryUDP(ctx context.Context, addr, name string, qtype dnsmessage.Type) (answer, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	id := randomID()
	q, err := buildQuery(id, name, qtype)
	if err != nil {
		return answer{}, err
	}
	c, err := r.n.Dial(ctx, Module, "udp", addr)
	if err != nil {
		return answer{}, err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(q); err != nil {
		return answer{}, err
	}
	buf := make([]byte, 4096)
	for {
		k, err := c.Read(buf)
		if err != nil {
			return answer{}, err
		}
		a, err := parseAnswer(buf[:k], id, qtype)
		if errors.Is(err, errMismatch) {
			continue
		}
		return a, err
	}
}

func (r *runner) queryDoT(ctx context.Context, addr, serverName, name string, qtype dnsmessage.Type) (answer, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	id := randomID()
	q, err := buildQuery(id, name, qtype)
	if err != nil {
		return answer{}, err
	}
	raw, err := r.n.Dial(ctx, Module, "tcp", addr)
	if err != nil {
		return answer{}, err
	}
	defer raw.Close()
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	}
	c := tls.Client(raw, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	if err := c.HandshakeContext(ctx); err != nil {
		return answer{}, err
	}
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(q)))
	if _, err := c.Write(append(frame, q...)); err != nil {
		return answer{}, err
	}
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return answer{}, err
	}
	msg := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, msg); err != nil {
		return answer{}, err
	}
	return parseAnswer(msg, id, qtype)
}

type httpStatusError int

func (e httpStatusError) Error() string { return fmt.Sprintf("HTTP %d", int(e)) }

func (r *runner) queryDoH(ctx context.Context, endpoint, name string, qtype dnsmessage.Type) (answer, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	q, err := buildQuery(0, name, qtype)
	if err != nil {
		return answer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(q))
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := r.n.HTTPClient(Module).Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return answer{}, httpStatusError(resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return answer{}, err
	}
	return parseAnswer(body, 0, qtype)
}

type transportResult struct {
	ans answer
	err error
}

func (r *runner) dns(ctx context.Context) []probe.Result {
	qtype := r.qtype()
	udp := make([]transportResult, len(r.resolvers))
	dot := make([]transportResult, len(r.resolvers))
	doh := map[string]*transportResult{}
	for _, rs := range r.resolvers {
		doh[rs.DoH] = &transportResult{}
	}
	var wg sync.WaitGroup
	run := func(dst *transportResult, fn func() (answer, error)) {
		wg.Go(func() {
			defer r.acquire()()
			dst.err = r.attempt(func() error {
				var err error
				dst.ans, err = fn()
				return err
			})
		})
	}
	for i, rs := range r.resolvers {
		run(&udp[i], func() (answer, error) {
			return r.queryUDP(ctx, net.JoinHostPort(rs.IP, "53"), availabilityDomain, qtype)
		})
		run(&dot[i], func() (answer, error) {
			return r.queryDoT(ctx, net.JoinHostPort(rs.IP, "853"), rs.DoT, availabilityDomain, qtype)
		})
	}
	for endpoint, dst := range doh {
		run(dst, func() (answer, error) { return r.queryDoH(ctx, endpoint, availabilityDomain, qtype) })
	}
	wg.Wait()

	var out []probe.Result
	refIdx, refDoH := -1, false
	for i, rs := range r.resolvers {
		name := rs.Name + " " + rs.IP
		out = append(out, udpResult(name, udp[i]))
		dohRes := encryptedResult(name+" DoH", *doh[rs.DoH])
		dohRes.Detail = joinDetail(dohRes.Detail, rs.DoH)
		out = append(out, dohRes)
		out = append(out, encryptedResult(name+" DoT", dot[i]))
		if dohRes.Status == probe.Yes && !refDoH {
			refIdx, refDoH = i, true
		}
		if refIdx < 0 && out[len(out)-1].Status == probe.Yes {
			refIdx = i
		}
	}
	for i := range out {
		out[i].Group = DNS
	}
	out = append(out, r.hijack(ctx, refIdx, refDoH)...)
	out = append(out, r.interception(ctx)...)
	return append(out, localChecks(r.n.Options().Family)...)
}

func udpResult(service string, t transportResult) probe.Result {
	res := probe.Result{Group: DNS, Service: service}
	if t.err != nil {
		res.Status, res.Reason = errStatus(t.err), describe(t.err)
		return res
	}
	res.Status, res.Reason = probe.Yes, "available"
	res.Detail = answerDetail(t.ans)
	return res
}

func encryptedResult(service string, t transportResult) probe.Result {
	res := probe.Result{Group: DNS, Service: service}
	var hs httpStatusError
	switch {
	case t.err == nil && len(t.ans.IPs) > 0:
		res.Status, res.Reason = probe.Yes, "available"
		res.Detail = answerDetail(t.ans)
	case t.err == nil:
		res.Status, res.Reason = probe.Unknown, "no address in answer ("+rcodeName(t.ans.RCode)+")"
	case errors.As(t.err, &hs):
		res.Status, res.Reason = probe.Unknown, hs.Error()
	case isX509(t.err):
		res.Status, res.Reason = probe.Unknown, "invalid certificate"
		res.Detail = probe.Truncate(t.err.Error(), 160)
	default:
		res.Status, res.Reason = errStatus(t.err), describe(t.err)
	}
	return res
}

func rcodeName(c dnsmessage.RCode) string {
	switch c {
	case dnsmessage.RCodeSuccess:
		return "NOERROR"
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE%d", int(c))
}

func answerDetail(a answer) string {
	s := rcodeName(a.RCode)
	if len(a.IPs) > 0 {
		s += " " + strings.Join(a.IPs, ", ")
	}
	return s
}

func joinDetail(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

type plainAnswer struct {
	Responded bool
	NXDomain  bool
	IPs       []string
}

func classifyPlain(a plainAnswer, reference []string) (probe.Status, string) {
	switch {
	case a.NXDomain:
		return probe.No, "spoofed (NXDOMAIN)"
	case !a.Responded || len(a.IPs) == 0:
		return probe.Unknown, "unreachable"
	}
	for _, ip := range a.IPs {
		if slices.Contains(reference, ip) {
			return probe.Yes, "clean"
		}
	}
	reason := "spoofed (" + a.IPs[0] + ")"
	if bogus(a.IPs) {
		reason += ", bogus address"
	}
	return probe.No, reason
}

func bogus(ips []string) bool {
	for _, s := range ips {
		if ip, err := netip.ParseAddr(s); err == nil && !netx.IsPublic(ip) {
			return true
		}
	}
	return false
}

func plainFromAnswer(a answer, err error) plainAnswer {
	if err != nil {
		return plainAnswer{}
	}
	return plainAnswer{Responded: true, NXDomain: a.RCode == dnsmessage.RCodeNameError, IPs: a.IPs}
}

func (r *runner) systemAnswer(ctx context.Context, name string) (plainAnswer, error) {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	addrs, err := r.n.LookupHost(ctx, Module, name)
	var dnsErr *net.DNSError
	switch {
	case errors.As(err, &dnsErr) && dnsErr.IsNotFound:
		return plainAnswer{Responded: true, NXDomain: true}, nil
	case err != nil:
		return plainAnswer{}, err
	}
	want6 := r.n.Options().Family == netx.IPv6
	pa := plainAnswer{Responded: true}
	for _, s := range addrs {
		if ip, err := netip.ParseAddr(s); err == nil && ip.Unmap().Is6() == want6 {
			pa.IPs = append(pa.IPs, ip.Unmap().String())
		}
	}
	return pa, nil
}

func (r *runner) hijack(ctx context.Context, refIdx int, refDoH bool) []probe.Result {
	summary := probe.Result{Group: DNS, Service: "DNS hijacking"}
	if r.n.Proxied() {
		summary.Status, summary.Reason = probe.Unknown, "plain DNS is disabled while a proxy is in effect"
		return []probe.Result{summary}
	}
	if refIdx < 0 {
		summary.Status, summary.Reason = probe.Unknown, "no DoH/DoT server reachable"
		return []probe.Result{summary}
	}
	ref := r.resolvers[refIdx]
	transport := "DoT"
	if refDoH {
		transport = "DoH"
	}
	refLabel := ref.Name + " (" + ref.IP + ") over " + transport
	qtype := r.qtype()

	var rows []probe.Result
	var refIPs []string
	checked, hijacked := "", false
	for _, domain := range hijackDomains {
		var refAns answer
		err := func() error {
			defer r.acquire()()
			return r.attempt(func() error {
				var err error
				if refDoH {
					refAns, err = r.queryDoH(ctx, ref.DoH, domain, qtype)
				} else {
					refAns, err = r.queryDoT(ctx, net.JoinHostPort(ref.IP, "853"), ref.DoT, domain, qtype)
				}
				return err
			})
		}()
		if err != nil || len(refAns.IPs) == 0 {
			continue
		}
		refIPs, checked = refAns.IPs, domain
		answers := make([]plainAnswer, len(r.resolvers)+1)
		var wg sync.WaitGroup
		for i, rs := range r.resolvers {
			wg.Go(func() {
				defer r.acquire()()
				var a answer
				err := r.attempt(func() error {
					var err error
					a, err = r.queryUDP(ctx, net.JoinHostPort(rs.IP, "53"), domain, qtype)
					return err
				})
				answers[i] = plainFromAnswer(a, err)
			})
		}
		wg.Go(func() {
			defer r.acquire()()
			a, err := r.systemAnswer(ctx, domain)
			if err == nil {
				answers[len(r.resolvers)] = a
			}
		})
		wg.Wait()

		rows = rows[:0]
		spoofed := 0
		for i, a := range answers {
			service := "System resolver spoofing"
			if i < len(r.resolvers) {
				service = r.resolvers[i].Name + " " + r.resolvers[i].IP + " spoofing"
			}
			st, reason := classifyPlain(a, refIPs)
			if st == probe.No {
				spoofed++
			}
			detail := domain
			if len(a.IPs) > 0 {
				detail += " → " + strings.Join(a.IPs, ", ")
			}
			rows = append(rows, probe.Result{Group: DNS, Service: service, Status: st, Reason: reason, Detail: detail})
		}
		if spoofed > 0 {
			hijacked = true
			summary.Status = probe.No
			summary.Reason = fmt.Sprintf("hijacking detected: %d of %d resolvers spoofed for %s", spoofed, len(answers), domain)
			break
		}
	}
	switch {
	case checked == "":
		summary.Status, summary.Reason = probe.Unknown, "reference resolver returned no addresses"
		return []probe.Result{summary}
	case !hijacked:
		summary.Status, summary.Reason = probe.Yes, "no DNS hijacking detected"
	}
	summary.Detail = "reference: " + refLabel + " → " + strings.Join(refIPs, ", ")
	return append(rows, summary)
}
