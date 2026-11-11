package datasrc

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"

	"github.com/arngory/cii/internal/config"
	"github.com/arngory/cii/internal/netx"
	"github.com/arngory/cii/internal/paths"
)

const maxDownload = 512 << 20

type ManifestEntry struct {
	ID         string    `json:"id"`
	File       string    `json:"file"`
	URL        string    `json:"url"`
	FetchedAt  time.Time `json:"fetched_at"`
	BuildEpoch uint      `json:"build_epoch"`
	DBType     string    `json:"database_type"`
	SHA256     string    `json:"sha256"`
	Size       int64     `json:"size"`
	License    string    `json:"license"`
}

type Manifest struct {
	Entries map[string]ManifestEntry `json:"entries"`
}

func LoadManifest(dir string) (*Manifest, error) {
	m := &Manifest{Entries: map[string]ManifestEntry{}}
	b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if errors.Is(err, os.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Entries == nil {
		m.Entries = map[string]ManifestEntry{}
	}
	return m, nil
}

func (m *Manifest) save(dir string) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return paths.WriteFileAtomic(filepath.Join(dir, "manifest.json"), b, 0o644)
}

func loadOrResetManifest(dir string) *Manifest {
	if m, err := LoadManifest(dir); err == nil {
		return m
	}
	return &Manifest{Entries: map[string]ManifestEntry{}}
}

func Update(ctx context.Context, n *netx.Net, dir string, src Source, keys config.Keys) (ManifestEntry, error) {
	candidates, user, pass, err := src.urls(time.Now(), keys)
	if err != nil {
		return ManifestEntry{}, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ManifestEntry{}, err
	}
	client := n.HTTPClient(Module)
	client.Timeout = 10 * time.Minute
	m := loadOrResetManifest(dir)

	var lastErr error
	for _, u := range candidates {
		entry, err := fetch(ctx, client, dir, src, u, user, pass)
		if err == nil {
			m.Entries[src.ID] = entry
			return entry, m.save(dir)
		}
		lastErr = err
		var nf notFound
		if !errors.As(err, &nf) {
			break
		}
	}
	return ManifestEntry{}, lastErr
}

type notFound struct{ url string }

func (e notFound) Error() string { return "not found: " + e.url }

func fetch(ctx context.Context, c *http.Client, dir string, src Source, rawURL, user, pass string) (ManifestEntry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return ManifestEntry{}, err
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := c.Do(req)
	if err != nil {
		return ManifestEntry{}, netx.Redact(err)
	}
	defer resp.Body.Close()
	clean := netx.StripSecrets(rawURL)
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return ManifestEntry{}, notFound{clean}
	case resp.StatusCode != http.StatusOK:
		return ManifestEntry{}, fmt.Errorf("%s: HTTP %d", clean, resp.StatusCode)
	}

	body := io.Reader(io.LimitReader(resp.Body, maxDownload+1))
	switch src.Archive {
	case Gzip:
		zr, err := gzip.NewReader(body)
		if err != nil {
			return ManifestEntry{}, fmt.Errorf("%s: %w", clean, err)
		}
		defer zr.Close()
		body = zr
	case TarGz:
		zr, err := gzip.NewReader(body)
		if err != nil {
			return ManifestEntry{}, fmt.Errorf("%s: %w", clean, err)
		}
		defer zr.Close()
		body, err = mmdbFromTar(tar.NewReader(zr))
		if err != nil {
			return ManifestEntry{}, fmt.Errorf("%s: %w", clean, err)
		}
	}

	final := filepath.Join(dir, src.ID+".mmdb")
	tmp, err := os.CreateTemp(dir, src.ID+".*.tmp")
	if err != nil {
		return ManifestEntry{}, err
	}
	defer os.Remove(tmp.Name())
	h := sha256.New()
	size, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(body, maxDownload+1))
	if serr := tmp.Sync(); err == nil {
		err = serr
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil && size > maxDownload {
		err = fmt.Errorf("exceeds %d bytes", maxDownload)
	}
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("%s: %w", clean, err)
	}

	db, err := maxminddb.Open(tmp.Name())
	if err != nil {
		return ManifestEntry{}, fmt.Errorf("%s: downloaded file is not a valid MaxMind DB: %w", clean, err)
	}
	meta := db.Metadata
	db.Close()

	if err := os.Rename(tmp.Name(), final); err != nil {
		return ManifestEntry{}, err
	}
	return ManifestEntry{
		ID: src.ID, File: filepath.Base(final), URL: clean, FetchedAt: time.Now().UTC(),
		BuildEpoch: meta.BuildEpoch, DBType: meta.DatabaseType,
		SHA256: hex.EncodeToString(h.Sum(nil)), Size: size, License: src.License,
	}, nil
}

func mmdbFromTar(tr *tar.Reader) (io.Reader, error) {
	for {
		hdr, err := tr.Next()
		if err != nil {
			return nil, fmt.Errorf("no .mmdb in archive: %w", err)
		}
		if hdr.Typeflag == tar.TypeReg && strings.HasSuffix(hdr.Name, ".mmdb") {
			return tr, nil
		}
	}
}
