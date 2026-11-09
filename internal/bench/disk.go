package bench

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unsafe"
)

type DiskResult struct {
	Block      string  `json:"block"`
	ReadMBps   float64 `json:"read_mbps"`
	WriteMBps  float64 `json:"write_mbps"`
	ReadIOPS   float64 `json:"read_iops"`
	WriteIOPS  float64 `json:"write_iops"`
	Direct     bool    `json:"direct_io"`
	DurationMs int64   `json:"duration_ms"`
}

type DiskReport struct {
	Path       string       `json:"path"`
	SizeBytes  int64        `json:"size_bytes"`
	Direct     bool         `json:"direct_io"`
	Sequential DiskResult   `json:"sequential"`
	Random     []DiskResult `json:"random"`
}

var blockSizes = []struct {
	name string
	size int
}{{"4k", 4 << 10}, {"64k", 64 << 10}, {"512k", 512 << 10}, {"1m", 1 << 20}}

const (
	minDiskSize    = 64 << 20
	randomDuration = 4 * time.Second
	queueDepth     = 8
)

func DiskTest(ctx context.Context, dir string, size int64) (DiskReport, error) {
	return diskTest(ctx, dir, max(size, minDiskSize), randomDuration)
}

func diskTest(ctx context.Context, dir string, size int64, randDur time.Duration) (DiskReport, error) {
	if dir == "" {
		dir = os.TempDir()
	}
	size -= size % (1 << 20)
	free, err := freeSpace(dir)
	if err == nil && free < uint64(size)*2 {
		return DiskReport{}, fmt.Errorf("%s has %d MiB free, need %d MiB", dir, free>>20, (size*2)>>20)
	}
	f, direct, err := openDirect(filepath.Join(dir, fmt.Sprintf(".cii-bench-%d", os.Getpid())))
	if err != nil {
		return DiskReport{}, err
	}
	defer func() {
		f.Close()
		os.Remove(f.Name())
	}()
	rep := DiskReport{Path: dir, SizeBytes: size, Direct: direct}

	seq, err := sequential(ctx, f, size)
	if err != nil {
		return DiskReport{}, err
	}
	seq.Direct = direct
	rep.Sequential = seq

	for _, bs := range blockSizes {
		if ctx.Err() != nil {
			return rep, ctx.Err()
		}
		r := randomRW(ctx, f, size, bs.size, randDur)
		r.Block, r.Direct = bs.name, direct
		rep.Random = append(rep.Random, r)
	}
	return rep, nil
}

func sequential(ctx context.Context, f *os.File, size int64) (DiskResult, error) {
	const chunk = 1 << 20
	buf := alignedBuffer(chunk)
	rand.Read(buf)
	start := time.Now()
	var written int64
	for written < size {
		if ctx.Err() != nil {
			return DiskResult{}, ctx.Err()
		}
		n, err := f.WriteAt(buf, written)
		if err != nil {
			return DiskResult{}, fmt.Errorf("write: %w", err)
		}
		written += int64(n)
	}
	if err := f.Sync(); err != nil {
		return DiskResult{}, err
	}
	wdur := time.Since(start)
	start = time.Now()
	var read int64
	for read < size {
		if ctx.Err() != nil {
			return DiskResult{}, ctx.Err()
		}
		n, err := f.ReadAt(buf, read)
		if err != nil && !errors.Is(err, context.Canceled) {
			if n == 0 {
				return DiskResult{}, fmt.Errorf("read: %w", err)
			}
		}
		read += int64(n)
	}
	rdur := time.Since(start)
	return DiskResult{Block: "1m seq", WriteMBps: mbps(size, wdur), ReadMBps: mbps(size, rdur), DurationMs: (wdur + rdur).Milliseconds()}, nil
}

func randomRW(ctx context.Context, f *os.File, size int64, bs int, dur time.Duration) DiskResult {
	ctx, cancel := context.WithTimeout(ctx, dur)
	defer cancel()
	blocks := size / int64(bs)
	var mu sync.Mutex
	var rbytes, wbytes, rops, wops int64
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < queueDepth; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			buf := alignedBuffer(bs)
			rand.Read(buf)
			x := uint64(seed*7919 + 1)
			var lr, lw, lro, lwo int64
			for ctx.Err() == nil {
				x ^= x << 13
				x ^= x >> 7
				x ^= x << 17
				off := int64(x%uint64(blocks)) * int64(bs)
				if x&1 == 0 {
					if n, err := f.ReadAt(buf, off); err == nil {
						lr += int64(n)
						lro++
					}
				} else {
					if n, err := f.WriteAt(buf, off); err == nil {
						lw += int64(n)
						lwo++
					}
				}
			}
			mu.Lock()
			rbytes, wbytes, rops, wops = rbytes+lr, wbytes+lw, rops+lro, wops+lwo
			mu.Unlock()
		}(int64(w))
	}
	wg.Wait()
	f.Sync()
	el := time.Since(start)
	return DiskResult{
		ReadMBps: mbps(rbytes, el), WriteMBps: mbps(wbytes, el),
		ReadIOPS: float64(rops) / el.Seconds(), WriteIOPS: float64(wops) / el.Seconds(),
		DurationMs: el.Milliseconds(),
	}
}

func mbps(b int64, d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(b) / 1e6 / d.Seconds()
}

func alignedBuffer(n int) []byte {
	const align = 4096
	raw := make([]byte, n+align)
	off := int(align - uintptr(unsafe.Pointer(unsafe.SliceData(raw)))%align)
	if off == align {
		off = 0
	}
	return raw[off : off+n]
}
