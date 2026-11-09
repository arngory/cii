package bench

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"runtime"
	"sync"
	"time"
)

type CPUReport struct {
	Single   CPUScore `json:"single"`
	Multi    CPUScore `json:"multi"`
	Threads  int      `json:"threads"`
	Duration int64    `json:"duration_ms"`
}

type CPUScore struct {
	SHA256MBps  float64 `json:"sha256_mbps"`
	AESGCMMBps  float64 `json:"aes_gcm_mbps"`
	DeflateMBps float64 `json:"deflate_mbps"`
	Score       float64 `json:"score"`
}

const (
	cpuRound     = 1 << 20
	cpuPerTest   = 1500 * time.Millisecond
	referenceMBs = 1000.0
)

func CPUTest(ctx context.Context) CPUReport { return cpuTest(ctx, cpuPerTest) }

func cpuTest(ctx context.Context, per time.Duration) CPUReport {
	start := time.Now()
	n := runtime.NumCPU()
	single := runWorkloads(ctx, 1, per)
	multi := single
	if n > 1 {
		multi = runWorkloads(ctx, n, per)
	}
	return CPUReport{Single: single, Multi: multi, Threads: n, Duration: time.Since(start).Milliseconds()}
}

func runWorkloads(ctx context.Context, threads int, per time.Duration) CPUScore {
	s := CPUScore{
		SHA256MBps:  throughput(ctx, threads, per, shaRound),
		AESGCMMBps:  throughput(ctx, threads, per, aesRound),
		DeflateMBps: throughput(ctx, threads, per, deflateRound),
	}
	s.Score = (s.SHA256MBps + s.AESGCMMBps + s.DeflateMBps*4) / referenceMBs * 100
	return s
}

func throughput(ctx context.Context, threads int, per time.Duration, round func(ctx context.Context, buf []byte) bool) float64 {
	ctx, cancel := context.WithTimeout(ctx, per)
	defer cancel()
	var mu sync.Mutex
	var total int64
	var wg sync.WaitGroup
	start := time.Now()
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func(seed uint64) {
			defer wg.Done()
			buf := make([]byte, cpuRound)
			fillText(buf, seed)
			var n int64
			for round(ctx, buf) {
				n += cpuRound
			}
			mu.Lock()
			total += n
			mu.Unlock()
		}(uint64(i))
	}
	wg.Wait()
	return float64(total) / 1e6 / time.Since(start).Seconds()
}

func fillText(buf []byte, seed uint64) {
	x := seed*0x9E3779B97F4A7C15 | 1
	next := func() uint64 {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		return x
	}
	var words [512][]byte
	for i := range words {
		w := make([]byte, 3+next()%8)
		for j := range w {
			w[j] = 'a' + byte(next()%26)
		}
		words[i] = w
	}
	for n := 0; n < len(buf); {
		n += copy(buf[n:], words[next()%uint64(len(words))])
		if n < len(buf) {
			buf[n] = ' '
			n++
		}
	}
}

func shaRound(ctx context.Context, buf []byte) bool {
	if ctx.Err() != nil {
		return false
	}
	sum := sha256.Sum256(buf)
	buf[0] ^= sum[0]
	return true
}

var aesKey = bytes.Repeat([]byte{0x42}, 32)

func aesRound(ctx context.Context, buf []byte) bool {
	if ctx.Err() != nil {
		return false
	}
	block, _ := aes.NewCipher(aesKey)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, gcm.NonceSize())
	out := gcm.Seal(nil, nonce, buf, nil)
	buf[0] ^= out[len(out)-1]
	return true
}

func deflateRound(ctx context.Context, buf []byte) bool {
	if ctx.Err() != nil {
		return false
	}
	var sink bytes.Buffer
	w, _ := flate.NewWriter(&sink, flate.DefaultCompression)
	w.Write(buf)
	w.Close()
	buf[0] ^= byte(sink.Len())
	return true
}
