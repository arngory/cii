package censor

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/arngory/cii/internal/probe"
)

const (
	mtprotoHeaderBytes = 64
	mtprotoReplyBytes  = 44
)

var (
	intermediateTag = []byte{0xee, 0xee, 0xee, 0xee}
	reqPQMulti      = []byte{0xf1, 0x8e, 0x7e, 0xbe}
	resPQ           = []byte{0x63, 0x24, 0x16, 0x05}
	forbiddenStarts = [][]byte{
		[]byte("HEAD"), []byte("POST"), []byte("GET "), []byte("OPTI"),
		{0xdd, 0xdd, 0xdd, 0xdd}, {0xee, 0xee, 0xee, 0xee}, {0x16, 0x03, 0x01, 0x02},
	}
	errBadReply = errors.New("unexpected MTProto reply")
)

type hello struct {
	Wire   []byte
	Nonce  []byte
	decKey []byte
	decIV  []byte
}

func randomHeader(r io.Reader) ([]byte, error) {
	h := make([]byte, mtprotoHeaderBytes)
	for {
		if _, err := io.ReadFull(r, h); err != nil {
			return nil, err
		}
		if h[0] == 0xef || bytes.Equal(h[4:8], []byte{0, 0, 0, 0}) {
			continue
		}
		if slices.ContainsFunc(forbiddenStarts, func(p []byte) bool { return bytes.Equal(h[:4], p) }) {
			continue
		}
		return h, nil
	}
}

func newHello(r io.Reader, dc int, now time.Time) (*hello, error) {
	h, err := randomHeader(r)
	if err != nil {
		return nil, err
	}
	copy(h[56:60], intermediateTag)
	h[60], h[61] = byte(dc), 0
	nonce := make([]byte, 16)
	if _, err := io.ReadFull(r, nonce); err != nil {
		return nil, err
	}
	req := make([]byte, 0, 44)
	req = binary.LittleEndian.AppendUint32(req, 40)
	req = append(req, make([]byte, 8)...)
	req = binary.LittleEndian.AppendUint64(req, uint64(uint32(now.Unix()))<<32)
	req = binary.LittleEndian.AppendUint32(req, 20)
	req = append(req, reqPQMulti...)
	req = append(req, nonce...)

	plain := append(slices.Clone(h), req...)
	sealed := make([]byte, len(plain))
	enc, err := ctrStream(h[8:40], h[40:56])
	if err != nil {
		return nil, err
	}
	enc.XORKeyStream(sealed, plain)

	rev := slices.Clone(h[8:56])
	slices.Reverse(rev)
	wire := append(slices.Clone(h[:56]), sealed[56:]...)
	return &hello{Wire: wire, Nonce: nonce, decKey: rev[:32], decIV: rev[32:48]}, nil
}

func ctrStream(key, iv []byte) (cipher.Stream, error) {
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewCTR(b, iv), nil
}

func (h *hello) check(reply []byte) error {
	if len(reply) != mtprotoReplyBytes {
		return errBadReply
	}
	dec, err := ctrStream(h.decKey, h.decIV)
	if err != nil {
		return err
	}
	plain := make([]byte, len(reply))
	dec.XORKeyStream(plain, reply)
	if !bytes.Equal(plain[24:28], resPQ) || !bytes.Equal(plain[28:44], h.Nonce) {
		return errBadReply
	}
	return nil
}

type phaseError struct{ err error }

func (e *phaseError) Error() string { return e.err.Error() }
func (e *phaseError) Unwrap() error { return e.err }

func (r *runner) mtprotoExchange(ctx context.Context, addr string, dc int) error {
	ctx, cancel := r.timeoutCtx(ctx)
	defer cancel()
	h, err := newHello(rand.Reader, dc, time.Now())
	if err != nil {
		return err
	}
	c, err := r.n.Dial(ctx, Module, "tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := c.Write(h.Wire); err != nil {
		return &phaseError{err}
	}
	reply := make([]byte, mtprotoReplyBytes)
	if _, err := io.ReadFull(c, reply); err != nil {
		return &phaseError{err}
	}
	if err := h.check(reply); err != nil {
		return &phaseError{err}
	}
	return nil
}

func (r *runner) telegram(ctx context.Context) []probe.Result {
	out := make([]probe.Result, len(r.dcs))
	var wg sync.WaitGroup
	for i, dc := range r.dcs {
		wg.Go(func() {
			defer r.acquire()()
			err := r.attempt(func() error {
				return r.mtprotoExchange(ctx, net.JoinHostPort(dc.IP, telegramPort), dc.ID)
			})
			out[i] = telegramResult("DC"+strconv.Itoa(dc.ID)+" "+dc.IP, err)
		})
	}
	wg.Wait()
	return out
}

func telegramResult(service string, err error) probe.Result {
	res := probe.Result{Group: Telegram, Service: service}
	var pe *phaseError
	switch {
	case err == nil:
		res.Status, res.Reason = probe.Yes, "MTProto handshake OK"
	case errors.Is(err, errBadReply):
		res.Status, res.Reason = probe.No, "unexpected MTProto reply"
	case errors.As(err, &pe):
		res.Status, res.Reason = probe.No, "no MTProto reply: "+describe(err)
		res.Detail = "TCP connected, handshake dropped (likely DPI)"
	default:
		res.Status, res.Reason = errStatus(err), describe(err)
		if res.Status == probe.No {
			res.Detail = "TCP connect failed"
		}
	}
	return res
}
