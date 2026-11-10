package risk

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/probe"
)

const smtpService = "Outbound SMTP (25)"

func checkSMTP(ctx context.Context, d dialer, opts MailOptions, timeout time.Duration) probe.Result {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	res := probe.Result{Group: Mail, Service: smtpService}
	host := opts.host()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := d.Dial(ctx, Module, "tcp", net.JoinHostPort(host, strconv.Itoa(opts.port())))
	if err != nil {
		res.Status, res.Detail, res.Reason = dialFailure(err)
		if res.Detail != "" {
			res.Detail += " (" + host + ")"
		}
		return res
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	banner, err := readReply(bufio.NewReader(conn))
	switch {
	case err != nil && netx.IsTimeout(err):
		res.Status, res.Detail = probe.No, "connected to "+host+", no SMTP banner (timeout)"
		return res
	case err != nil && banner == "":
		res.Status, res.Detail = probe.No, "connected to "+host+", closed without banner"
		return res
	}
	io.WriteString(conn, "QUIT\r\n")
	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	readReply(bufio.NewReader(conn))
	res.Detail = probe.Truncate(banner, 120)
	if strings.HasPrefix(banner, "220") {
		res.Status = probe.Yes
	} else {
		res.Status = probe.No
	}
	return res
}

func dialFailure(err error) (probe.Status, string, string) {
	if be := netx.AsBlocked(err); be != nil {
		return probe.Failed, "", "blocked by policy: " + be.Host
	}
	var dnsErr *net.DNSError
	switch {
	case errors.Is(err, netx.ErrProxyRaw):
		return probe.Unknown, "", proxyReason
	case errors.As(err, &dnsErr):
		return probe.Failed, "", probe.Truncate("resolve: "+dnsErr.Err, 120)
	case netx.IsTimeout(err):
		return probe.No, "connection timed out, port 25 likely filtered", ""
	case netx.IsRefused(err):
		return probe.No, "connection refused", ""
	case netx.IsReset(err):
		return probe.No, "connection reset", ""
	case netx.IsUnreachable(err):
		return probe.Failed, "", "network unreachable"
	}
	return probe.Failed, "", probe.Truncate(err.Error(), 120)
}

func readReply(r *bufio.Reader) (string, error) {
	var first string
	for range 32 {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if first == "" {
			first = line
		}
		if err != nil {
			return first, err
		}
		if len(line) < 4 || line[3] != '-' {
			return first, nil
		}
	}
	return first, nil
}
