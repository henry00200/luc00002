//go:build linux

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	defaultEngineVersion     = "v26.10.21"
	defaultRuntimeDir        = "/tmp/bp-runtime"
	defaultRuntimeConfigPath = "/tmp/bp-runtime/config.json"
	defaultEngineMemMB       = 550

	templateUUIDv4   = "24c8b9d5-4e71-4a8e-a96c-13d8a5726201"
	templateUUIDv6   = "e7f2b1c4-9a3d-4c5e-8b6f-7123d4e5f602"
	templateTrojanV4 = "c9f4a8b7e2d14a5c9b6e8f1a2b3c4d5e"
	templateTrojanV6 = "f1e2d3c4b5a67890123456789abcdef0"

	defaultLoopbackXH = "127.0.0.1:18443"
	defaultLoopbackWS = "127.0.0.1:18444"
	defaultLoopbackTR = "127.0.0.1:18445"

	fastProbeWindow       = 1500 * time.Millisecond
	fastProbeInterval     = 25 * time.Millisecond
	slowProbeInterval     = 3 * time.Second
	degradedProbeInterval = 250 * time.Millisecond
	minProbeNowInterval   = 1 * time.Second
	probeDialTimeout      = 250 * time.Millisecond
	defaultStartTimeout   = 10 * time.Second
	defaultStopTimeout    = 6 * time.Second
	pipeReadBufferSize    = 64 * 1024

	stableWindow       = 60 * time.Second
	initialBackoff     = 80 * time.Millisecond
	maxBackoffInterval = 5 * time.Second
	backoffJitterFrac  = 0.20

	healthGenShift      = 8
	prSetChildSubreaper = 36
)

const (
	healthRunning uint64 = 1 << iota
	healthReady
	healthXH
	healthWS
	healthTR
)

var defaultPortalPorts = []string{"443", "2053", "2083", "2087", "2096", "8443"}

var scannerBufPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, pipeReadBufferSize) },
}

var pumpLogMu sync.Mutex
var pumpNewline = [1]byte{'\n'}

var sealedBaseURL = []byte{
	189, 105, 0, 113, 98, 220, 238, 163, 174, 252, 75, 239, 92, 219, 61, 220,
	183, 62, 154, 97, 44, 55, 94, 202, 254, 163, 249, 189, 141, 145, 165, 111,
	238, 187, 65, 215, 87, 58, 38, 77, 84, 44, 154, 115, 212, 161, 62, 72,
	65, 37, 245, 177,
}

var sealedApiURL = []byte{
	189, 105, 0, 113, 98, 220, 238, 163, 168, 229, 86, 169, 78, 208, 103, 215,
	173, 49, 155, 90, 23, 22, 34, 151, 195, 161, 247, 183, 143, 170, 158, 81,
	216, 187, 107, 192, 90, 38, 106, 93, 94, 45, 208, 56, 201, 179, 60, 65,
	79, 55, 244, 237, 147, 129, 171, 34, 117, 137, 139, 251, 177, 182, 58,
}

var embeddedConfigGzip = []byte{
	31, 139, 8, 0, 207, 76, 219, 106, 2, 255, 229, 87, 89, 111, 227, 54, 16, 254, 47, 122,
	150, 108, 81, 151, 101, 63, 117, 79, 52, 232, 145, 160, 206, 2, 11, 44, 242, 64, 145, 163,
	88, 13, 45, 105, 73, 202, 137, 186, 200, 127, 239, 12, 37, 31, 202, 102, 211, 108, 209, 93,
	39, 68, 144, 193, 247, 60, 247, 206, 61, 247, 221, 187, 107, 230, 208, 190, 215, 209, 113, 109,
	107, 16, 181, 177, 233, 201, 215, 162, 109, 74, 91, 18, 93, 91, 145, 114, 140, 168, 246, 75,
	157, 181, 80, 147, 13, 41, 163, 146, 218, 150, 211, 209, 168, 140, 101, 102, 113, 125, 41, 11,
	235, 116, 210, 106, 32, 141, 172, 70, 147, 157, 141, 162, 50, 213, 230, 204, 210, 25, 148, 146,
	246, 178, 147, 162, 174, 82, 90, 171, 74, 201, 169, 132, 140, 68, 101, 46, 151, 182, 137, 148,
	21, 213, 110, 117, 164, 166, 24, 76, 113, 117, 72, 104, 140, 117, 74, 229, 36, 189, 78, 233,
	86, 214, 49, 130, 186, 21, 149, 153, 97, 173, 20, 147, 85, 93, 137, 229, 213, 37, 117, 132,
	200, 161, 76, 112, 150, 105, 49, 200, 155, 66, 177, 153, 235, 237, 210, 24, 161, 173, 17, 149,
	219, 180, 222, 168, 174, 138, 220, 148, 146, 101, 169, 221, 8, 116, 150, 39, 147, 113, 130, 186,
	209, 106, 32, 45, 147, 19, 87, 195, 210, 166, 114, 163, 182, 100, 161, 88, 77, 181, 195, 101,
	71, 85, 26, 73, 206, 92, 177, 114, 179, 132, 70, 83, 137, 88, 173, 186, 232, 48, 180, 17,
	148, 155, 229, 252, 9, 145, 210, 164, 147, 36, 215, 236, 168, 157, 118, 104, 143, 232, 17, 132,
	191, 197, 139, 241, 15, 62, 248, 225, 23, 7, 219, 255, 248, 243, 199, 15, 191, 249, 227, 207,
	254, 254, 251, 127, 255, 247, 247, 207, 191, 253, 227, 239, 254, 254, 187, 127, 248, 245, 215, 127,
	253, 246, 219, 223, 251, 251, 159, 222, 238, 181, 19, 238, 62, 121, 127, 247, 245, 215, 207, 127,
	250, 246, 251, 223, 254, 238, 111, 255, 248, 243, 251, 191, 249, 233, 215, 127, 254, 249, 231, 207,
	127, 249, 235, 183, 223, 254, 246, 231, 191, 248, 249, 211, 111, 255, 241, 211, 175, 127, 244, 234,
	235, 207, 127, 244, 234, 155, 255, 252, 230, 247, 207, 127, 252, 241, 247, 223, 252, 254, 247, 191,
	249, 230, 187, 255, 249, 243, 111, 255, 250, 247, 191, 253, 241, 235, 111, 255, 243, 211, 111, 255,
	251, 235, 127, 254, 241, 235, 191, 253, 230, 187, 191, 255, 252, 231, 255, 253, 243, 211, 255, 252,
	243, 211, 207, 127, 250, 230, 111, 255, 250, 235, 239, 127, 248, 245, 207, 255, 244, 245, 219, 127,
	253, 249, 219, 223, 251, 251, 111, 255, 253, 251, 223, 255, 251, 235, 175, 127, 248, 243, 235, 207,
	127, 250, 238, 175, 127, 246, 238, 187, 255, 250, 249, 247, 223, 252, 244, 227, 207, 127, 250, 235,
	175, 127, 253, 254, 251, 127, 254, 253, 251, 191, 251, 245, 175, 127, 249, 235, 175, 127, 252, 249,
	219, 223, 250, 249, 219, 223, 254, 249, 155, 127, 248, 249, 219, 127, 252, 244, 211, 111, 255, 251,
	243, 211, 111, 255, 254, 249, 247, 223, 252, 249, 211, 175, 127, 248, 249, 235, 207, 127, 252, 244,
	211, 207, 127, 248, 249, 247, 223, 254, 249, 231, 207, 127, 252, 249, 247, 223, 252, 244, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
	254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223,
	254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223,
	252, 254, 247, 223, 252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223,
	252, 249, 247, 223, 254, 251, 247, 223, 254, 249, 247, 223, 252, 254, 247, 223, 252, 249, 247, 223,
}

type BermudaCredentials struct {
	MasterKey     string `json:"master_key"`
	UUIDv4        string `json:"uuid_v4"`
	UUIDv6        string `json:"uuid_v6"`
	TrojanV4      string `json:"trojan_v4"`
	TrojanV6      string `json:"trojan_v6"`
	AutoGenerated bool   `json:"auto_generated,omitempty"`
}

type supervisorBundlePayload struct {
	Version          int               `json:"v"`
	LucityDomain     string            `json:"lucity_domain"`
	CloudflareDomain string            `json:"cloudflare_domain,omitempty"`
	ActiveDomain     string            `json:"active_domain"`
	Region           string            `json:"region"`
	MasterKey        string            `json:"master_key"`
	UUIDv4           string            `json:"uuid_v4"`
	UUIDv6           string            `json:"uuid_v6"`
	TrojanV4         string            `json:"trojan_v4"`
	TrojanV6         string            `json:"trojan_v6"`
	Paths            map[string]string `json:"paths"`
	Ports            []string          `json:"ports"`
	CreatedAt        int64             `json:"created_at"`
}

func unsealString(b []byte) string {
	key := "bermuda-engine-seed-v1"
	out := make([]byte, len(b))
	offset := 0
	blockIdx := 0
	for offset < len(b) {
		mac := hmac.New(sha256.New, []byte(key))
		_, _ = mac.Write([]byte(fmt.Sprintf("slot-%d", blockIdx)))
		keystream := mac.Sum(nil)
		for _, k := range keystream {
			if offset >= len(b) {
				break
			}
			out[offset] = b[offset] ^ k
			offset++
		}
		blockIdx++
	}
	return string(out)
}

func extractDigestSHA256(raw []byte) string {
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		if strings.HasPrefix(upper, "SHA256") || strings.HasPrefix(upper, "SHA2-256") {
			if _, after, ok := strings.Cut(line, "="); ok {
				clean := strings.TrimSpace(after)
				if len(clean) == 64 {
					return clean
				}
			}
		}
	}
	return ""
}

type ghReleaseItem struct {
	TagName string `json:"tag_name"`
}

func resolveLatestEngineTag(client *http.Client, apiURL string) string {
	req, err := http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Bermuda-Bootstrapper/4.0")
	resp, err := client.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		if resp != nil {
			_ = resp.Body.Close()
		}
		return ""
	}
	defer resp.Body.Close()
	var items []ghReleaseItem
	if err := json.NewDecoder(resp.Body).Decode(&items); err == nil && len(items) > 0 {
		return strings.TrimSpace(items[0].TagName)
	}
	return ""
}

func fetchEngineZipAndDigest(client *http.Client, zipURL, dgstURL string) ([]byte, []byte, error) {
	reqZip, err := http.NewRequest(http.MethodGet, zipURL, nil)
	if err != nil {
		return nil, nil, err
	}
	reqZip.Header.Set("User-Agent", "Bermuda-Bootstrapper/4.0")
	respZip, err := client.Do(reqZip)
	if err != nil {
		return nil, nil, err
	}
	defer respZip.Body.Close()
	if respZip.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("zip download failed with status %d", respZip.StatusCode)
	}
	zipBytes, err := io.ReadAll(respZip.Body)
	if err != nil {
		return nil, nil, err
	}

	reqDgst, err := http.NewRequest(http.MethodGet, dgstURL, nil)
	if err != nil {
		return zipBytes, nil, nil
	}
	reqDgst.Header.Set("User-Agent", "Bermuda-Bootstrapper/4.0")
	respDgst, err := client.Do(reqDgst)
	if err != nil || respDgst.StatusCode != http.StatusOK {
		if respDgst != nil {
			_ = respDgst.Body.Close()
		}
		return zipBytes, nil, nil
	}
	defer respDgst.Body.Close()
	dgstBytes, _ := io.ReadAll(respDgst.Body)
	return zipBytes, dgstBytes, nil
}

func extractZipFile(f *zip.File, destPath string, mode os.FileMode) error {
	rc, err := f.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
		return err
	}

	out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, rc)
	return err
}

func ensureRuntimeEngineBootstrap() (binPath, assetDir string, err error) {
	baseDir := defaultRuntimeDir
	binTarget := filepath.Join(baseDir, "engine")
	geoIPTarget := filepath.Join(baseDir, "geoip.dat")
	geoSiteTarget := filepath.Join(baseDir, "geosite.dat")

	if explicit := getEnv("BERMUDA_ENGINE_BIN", getEnv("BERMUDA_XRAY_BIN", "")); explicit != "" {
		if info, err := os.Stat(explicit); err == nil && !info.IsDir() {
			return explicit, getEnv("XRAY_LOCATION_ASSET", baseDir), nil
		}
	}
	for _, candidate := range []string{"/usr/local/bin/xray", "/app/bin/xray"} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, getEnv("XRAY_LOCATION_ASSET", "/usr/local/share/xray"), nil
		}
	}
	if info, err := os.Stat(binTarget); err == nil && !info.IsDir() {
		return binTarget, baseDir, nil
	}

	_ = os.MkdirAll(baseDir, 0755)

	arch := runtime.GOARCH
	var zipArch string
	switch arch {
	case "amd64":
		zipArch = "64"
	case "arm64":
		zipArch = "arm64-v8a"
	default:
		zipArch = "64"
	}

	zipName := "Xray-linux-" + zipArch + ".zip"
	baseURL := unsealString(sealedBaseURL)
	apiURL := unsealString(sealedApiURL)
	version := defaultEngineVersion

	downloadURL := baseURL + version + "/" + zipName
	dgstURL := downloadURL + ".dgst"

	client := &http.Client{Timeout: 90 * time.Second}

	log.Printf("[Supervisor] Bootstrapping engine worker (%s, %s)...", version, zipArch)
	zipBytes, dgstBytes, dlErr := fetchEngineZipAndDigest(client, downloadURL, dgstURL)
	if dlErr != nil {
		log.Printf("[Supervisor] Pinned version %s unavailable (%v); discovering latest release...", version, dlErr)
		latestTag := resolveLatestEngineTag(client, apiURL)
		if latestTag == "" {
			return "", "", fmt.Errorf("resolve latest release: %w", dlErr)
		}
		downloadURL = baseURL + latestTag + "/" + zipName
		dgstURL = downloadURL + ".dgst"
		zipBytes, dgstBytes, dlErr = fetchEngineZipAndDigest(client, downloadURL, dgstURL)
		if dlErr != nil {
			return "", "", fmt.Errorf("download latest release %s: %w", latestTag, dlErr)
		}
		version = latestTag
	}

	expectedSHA := extractDigestSHA256(dgstBytes)
	if expectedSHA != "" {
		actualSHA := fmt.Sprintf("%x", sha256.Sum256(zipBytes))
		if !strings.EqualFold(expectedSHA, actualSHA) {
			return "", "", fmt.Errorf("engine verification failed (expected %s, got %s)", expectedSHA, actualSHA)
		}
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		return "", "", fmt.Errorf("read engine archive: %w", err)
	}

	for _, file := range zipReader.File {
		lowerName := strings.ToLower(file.Name)
		var destPath string
		var mode os.FileMode
		switch {
		case lowerName == "xray" || lowerName == "xray.exe":
			destPath = binTarget
			mode = 0755
		case lowerName == "geoip.dat":
			destPath = geoIPTarget
			mode = 0644
		case lowerName == "geosite.dat":
			destPath = geoSiteTarget
			mode = 0644
		default:
			continue
		}

		if err := extractZipFile(file, destPath, mode); err != nil {
			return "", "", fmt.Errorf("extract %s: %w", file.Name, err)
		}
	}

	log.Printf("[Supervisor] Engine worker %s successfully initialized at %s", version, binTarget)
	return binTarget, baseDir, nil
}

func sanitizeMasterKey(raw string) string {
	s := strings.TrimSpace(raw)
	upper := strings.ToUpper(s)
	if strings.HasPrefix(upper, "BERMUDA_MASTER_KEY") || strings.HasPrefix(upper, "MASTER_KEY") {
		if _, after, ok := strings.Cut(s, "="); ok {
			s = strings.TrimSpace(after)
		}
	}
	s = strings.Trim(s, "\"'` \t\r\n")
	s = strings.TrimSpace(s)
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func sanitizeExplicitCredential(raw string) string {
	s := strings.Trim(strings.TrimSpace(raw), "\"'` \t\r\n")
	if strings.Contains(s, "${{") || strings.HasPrefix(s, "$") {
		return ""
	}
	return s
}

func hmacSHA256(key, label string) [32]byte {
	mac := hmac.New(sha256.New, []byte(key))
	_, _ = mac.Write([]byte(label))
	var out [32]byte
	copy(out[:], mac.Sum(nil))
	return out
}

func deriveUUID(masterKey, label string) string {
	sum := hmacSHA256(masterKey, label)
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func deriveHexPassword(masterKey, label string) string {
	sum := hmacSHA256(masterKey, label)
	return hex.EncodeToString(sum[:16])
}

func resolveRuntimeCredentials() BermudaCredentials {
	masterKey := sanitizeMasterKey(getEnv("BERMUDA_MASTER_KEY", getEnv("MASTER_KEY", "")))

	explicitV4 := sanitizeExplicitCredential(getEnv("BERMUDA_UUID_IPV4", ""))
	explicitV6 := sanitizeExplicitCredential(getEnv("BERMUDA_UUID_IPV6", ""))
	explicitTrV4 := sanitizeExplicitCredential(getEnv("BERMUDA_TROJAN_IPV4", ""))
	explicitTrV6 := sanitizeExplicitCredential(getEnv("BERMUDA_TROJAN_IPV6", ""))

	var autoGenerated bool
	if masterKey == "" && (explicitV4 == "" || explicitV6 == "" || explicitTrV4 == "" || explicitTrV6 == "") {
		autoGenerated = true
		var rnd [16]byte
		if _, err := rand.Read(rnd[:]); err != nil {
			masterKey = fmt.Sprintf("bmk-fallback-%d", time.Now().UnixNano())
		} else {
			masterKey = "bmk-" + hex.EncodeToString(rnd[:])
		}

		lcToken := sanitizeLucityToken(getEnv("LUCITY_API_TOKEN", getEnv("LUCITY_TOKEN", getEnv("BERMUDA_LUCITY_TOKEN", ""))))
		log.Println("[Supervisor] ========================================================================")
		if lcToken != "" {
			log.Printf("[Supervisor] Auto-generated new Master Key: %s", masterKey)
			log.Println("[Supervisor] LUCITY_API_TOKEN detected -> Master Key will be persisted automatically.")
		} else {
			log.Println("[Supervisor] NOTICE: BERMUDA_MASTER_KEY is not set in environment variables!")
			log.Printf("[Supervisor] Auto-generated Master Key: %s", masterKey)
			log.Println("[Supervisor] Set LUCITY_API_TOKEN or BERMUDA_MASTER_KEY in Lucity Variables to persist.")
		}
		log.Println("[Supervisor] ========================================================================")
	}

	creds := BermudaCredentials{
		MasterKey:     masterKey,
		UUIDv4:        deriveUUID(masterKey, "bermuda-vless-ipv4-v1"),
		UUIDv6:        deriveUUID(masterKey, "bermuda-vless-ipv6-v1"),
		TrojanV4:      deriveHexPassword(masterKey, "bermuda-trojan-ipv4-v1"),
		TrojanV6:      deriveHexPassword(masterKey, "bermuda-trojan-ipv6-v1"),
		AutoGenerated: autoGenerated,
	}

	if explicitV4 != "" {
		creds.UUIDv4 = explicitV4
	}
	if explicitV6 != "" {
		creds.UUIDv6 = explicitV6
	}
	if explicitTrV4 != "" {
		creds.TrojanV4 = explicitTrV4
	}
	if explicitTrV6 != "" {
		creds.TrojanV6 = explicitTrV6
	}

	return creds
}

func synthesizeRuntimeConfig(runtimePath string, creds BermudaCredentials) string {
	var rawBytes []byte
	if explicitPath := getEnv("BERMUDA_XRAY_CONFIG", ""); explicitPath != "" {
		if data, err := os.ReadFile(explicitPath); err == nil {
			rawBytes = data
		}
	}

	if len(rawBytes) == 0 {
		gzReader, err := gzip.NewReader(bytes.NewReader(embeddedConfigGzip))
		if err == nil {
			rawBytes, _ = io.ReadAll(gzReader)
			_ = gzReader.Close()
		}
	}

	if len(rawBytes) == 0 {
		log.Fatalf("[Supervisor] Fatal: unable to load base engine configuration")
	}

	ipv6Active := probeKernelIPv6Route()

	replacements := []string{
		templateUUIDv4, creds.UUIDv4,
		templateUUIDv6, creds.UUIDv6,
		templateTrojanV4, creds.TrojanV4,
		templateTrojanV6, creds.TrojanV6,
	}
	if !ipv6Active {
		replacements = append(replacements, `"UseIPv6v4"`, `"UseIPv4"`)
	}

	replacer := strings.NewReplacer(replacements...)
	synthesized := []byte(replacer.Replace(string(rawBytes)))

	if !json.Valid(synthesized) {
		log.Fatalf("[Supervisor] Fatal: synthesized configuration failed JSON validation")
	}

	_ = os.MkdirAll(filepath.Dir(runtimePath), 0755)
	tmpPath := runtimePath + ".tmp"
	if err := os.WriteFile(tmpPath, synthesized, 0600); err != nil {
		log.Fatalf("[Supervisor] Fatal: failed to write runtime temp config: %v", err)
	}
	if err := os.Rename(tmpPath, runtimePath); err != nil {
		_ = os.Remove(tmpPath)
		log.Fatalf("[Supervisor] Fatal: failed to commit runtime config: %v", err)
	}

	if ipv6Active {
		log.Printf("[Supervisor] Engine config synthesized at %s (Dual-Stack IPv6+IPv4 Egress: ACTIVE)", runtimePath)
	} else {
		log.Printf("[Supervisor] Engine config synthesized at %s (Safe IPv4 Fallback Active)", runtimePath)
	}
	return runtimePath
}

type SupervisorHealthSnapshot struct {
	Running     bool   `json:"running"`
	Ready       bool   `json:"ready"`
	Restarts    int32  `json:"restarts"`
	UptimeSec   int64  `json:"uptime_sec"`
	XHInbound   bool   `json:"xh_inbound_ok"`
	WSInbound   bool   `json:"ws_inbound_ok"`
	TRInbound   bool   `json:"tr_inbound_ok"`
	LastProbeAt string `json:"last_probe_at"`
	ChildPID    int    `json:"child_pid,omitempty"`
}

type childExit struct {
	pid    int
	status syscall.WaitStatus
	err    error
}

type processReaper struct {
	mu              sync.Mutex
	waiters         map[int]chan childExit
	subreaperActive bool
}

func newProcessReaper() (*processReaper, error) {
	r := &processReaper{
		waiters: make(map[int]chan childExit),
	}

	_, _, errno := syscall.RawSyscall6(
		syscall.SYS_PRCTL,
		uintptr(prSetChildSubreaper),
		1, 0, 0, 0, 0,
	)
	if errno != 0 {
		return r, fmt.Errorf("enable PR_SET_CHILD_SUBREAPER: %w", errno)
	}

	r.subreaperActive = true
	go r.reaperLoop()
	return r, nil
}

func (r *processReaper) reaperLoop() {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-1, &status, 0, nil)

		if errors.Is(err, syscall.EINTR) {
			continue
		}
		if errors.Is(err, syscall.ECHILD) {
			time.Sleep(50 * time.Millisecond)
			continue
		}
		if err != nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		r.mu.Lock()
		ch, ok := r.waiters[pid]
		if ok {
			delete(r.waiters, pid)
		}
		r.mu.Unlock()

		if ok && ch != nil {
			ch <- childExit{pid: pid, status: status}
			close(ch)
		}
	}
}

func (r *processReaper) StartProcess(name string, argv []string, attr *os.ProcAttr) (*os.Process, <-chan childExit, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, err := os.StartProcess(name, argv, attr)
	if err != nil {
		return nil, nil, err
	}

	ch := make(chan childExit, 1)
	if r.subreaperActive {
		r.waiters[p.Pid] = ch
	} else {
		pid := p.Pid
		go func() {
			var status syscall.WaitStatus
			for {
				_, werr := syscall.Wait4(pid, &status, 0, nil)
				if errors.Is(werr, syscall.EINTR) {
					continue
				}
				ch <- childExit{pid: pid, status: status, err: werr}
				close(ch)
				return
			}
		}()
	}
	return p, ch, nil
}

type Supervisor struct {
	binPath      string
	configPath   string
	assetDir     string
	creds        BermudaCredentials
	memLimitMB   int
	maxProcs     int
	xhAddr       string
	wsAddr       string
	trAddr       string
	startTimeout time.Duration
	stopTimeout  time.Duration

	reaper *processReaper

	mu               sync.Mutex
	proc             *os.Process
	startedAt        time.Time
	lastUptime       time.Duration
	runCancel        context.CancelFunc
	publicDomain     string
	lucityDomain     string
	cloudflareDomain string
	region           string

	runStarted    atomic.Bool
	stopRequested atomic.Bool
	restarts      atomic.Int32
	stopGraceNS   atomic.Int64
	runReady      chan struct{}
	stopped       chan struct{}

	state       atomic.Uint64
	lastProbeNS atomic.Int64

	probeMu     sync.Mutex
	probeDialer *net.Dialer
}

func NewSupervisor() *Supervisor {
	reaper, err := newProcessReaper()
	if err != nil {
		log.Printf("[Supervisor] Warning: Subreaper initialization: %v (using direct wait4 fallback)", err)
	}

	creds := resolveRuntimeCredentials()

	bin, assets, err := ensureRuntimeEngineBootstrap()
	if err != nil {
		log.Printf("[Supervisor] Warning: Engine runtime bootstrap: %v", err)
	}

	runtimeCfg := getEnv("BERMUDA_RUNTIME_CONFIG", defaultRuntimeConfigPath)
	activeCfg := synthesizeRuntimeConfig(runtimeCfg, creds)

	dialer := &net.Dialer{
		Timeout:   probeDialTimeout,
		KeepAlive: -1,
		Control: func(network, address string, c syscall.RawConn) error {
			var controlErr error
			err := c.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET,
					syscall.SO_LINGER, &syscall.Linger{Onoff: 1, Linger: 0})
			})
			if err != nil {
				return err
			}
			return controlErr
		},
	}

	s := &Supervisor{
		binPath:      bin,
		configPath:   activeCfg,
		assetDir:     assets,
		creds:        creds,
		memLimitMB:   getEnvInt("BERMUDA_XRAY_MEM_MB", defaultEngineMemMB),
		maxProcs:     getEnvInt("BERMUDA_XRAY_GOMAXPROCS", 0),
		xhAddr:       getEnv("BERMUDA_BACKEND_XH", defaultLoopbackXH),
		wsAddr:       getEnv("BERMUDA_BACKEND_WS", defaultLoopbackWS),
		trAddr:       getEnv("BERMUDA_BACKEND_TR", defaultLoopbackTR),
		startTimeout: defaultStartTimeout,
		stopTimeout:  defaultStopTimeout,
		reaper:       reaper,
		runReady:     make(chan struct{}),
		stopped:      make(chan struct{}),
		probeDialer:  dialer,
	}
	s.stopGraceNS.Store(int64(defaultStopTimeout))
	return s
}

func (s *Supervisor) Credentials() BermudaCredentials {
	return s.creds
}

func (s *Supervisor) MasterKey() string {
	return s.creds.MasterKey
}

func (s *Supervisor) IsMasterKeyAutoGenerated() bool {
	return s.creds.AutoGenerated
}

func (s *Supervisor) SetPublicDomain(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	clean := sanitizeDomainString(domain)
	s.publicDomain = clean
	if isLucityPublicDomain(clean) && s.lucityDomain == "" {
		s.lucityDomain = clean
	} else if clean != "" && !isLucityManagedDomain(clean) && s.cloudflareDomain == "" {
		s.cloudflareDomain = clean
	}
}

func (s *Supervisor) SetInfrastructureDomains(lucityDom, cfDom, reg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cleanLC := sanitizeDomainString(lucityDom); isLucityPublicDomain(cleanLC) {
		if s.lucityDomain == "" || (!isFullLucityServiceDomain(s.lucityDomain) && isFullLucityServiceDomain(cleanLC)) {
			s.lucityDomain = cleanLC
		}
	}
	if cleanCF := sanitizeDomainString(cfDom); cleanCF != "" && !isLucityManagedDomain(cleanCF) {
		s.cloudflareDomain = cleanCF
	}
	if strings.TrimSpace(reg) != "" {
		s.region = strings.TrimSpace(reg)
	}
}

func (s *Supervisor) GetInfrastructureDomains() (lucityDom, cfDom, reg string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lucityDomain, s.cloudflareDomain, s.region
}

func sanitizeDomainString(d string) string {
	d = strings.TrimSpace(d)
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimRight(d, "/")
	return strings.ToLower(strings.TrimSpace(d))
}

func buildPortalURL(domain, masterKey string) string {
	clean := sanitizeDomainString(domain)
	if clean == "" {
		return ""
	}
	scheme := "https"
	if strings.HasPrefix(clean, "127.0.0.1") || strings.HasPrefix(clean, "localhost") {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s/?bmk=%s", scheme, clean, url.QueryEscape(masterKey))
}

func (s *Supervisor) LogProvisioningLink(publicDomain string) {
	s.mu.Lock()
	lcDom := s.lucityDomain
	cfDom := s.cloudflareDomain
	pubDom := s.publicDomain
	reg := s.region
	s.mu.Unlock()

	if envLC, envCF := resolveInfrastructureDomains(); lcDom == "" || cfDom == "" {
		if lcDom == "" {
			lcDom = envLC
		}
		if cfDom == "" {
			cfDom = envCF
		}
	}

	if explicit := sanitizeDomainString(publicDomain); explicit != "" {
		if isLucityPublicDomain(explicit) && lcDom == "" {
			lcDom = explicit
		} else if !isLucityManagedDomain(explicit) && cfDom == "" {
			cfDom = explicit
		}
		pubDom = explicit
	}

	if reg == "" {
		rawReg := getEnv("BERMUDA_REGION", getEnv("LUCITY_REGION", getEnv("REGION", "")))
		reg = normalizeRegion(rawReg)
	}

	activeDom := cfDom
	if activeDom == "" {
		activeDom = lcDom
	}
	if activeDom == "" {
		activeDom = pubDom
	}
	if activeDom == "" {
		activeDom = "127.0.0.1:" + getEnv("PORT", "8080")
	}

	portsCopy := make([]string, len(defaultPortalPorts))
	copy(portsCopy, defaultPortalPorts)

	payload := supervisorBundlePayload{
		Version:          1,
		LucityDomain:     lcDom,
		CloudflareDomain: cfDom,
		ActiveDomain:     activeDom,
		Region:           reg,
		MasterKey:        s.creds.MasterKey,
		UUIDv4:           s.creds.UUIDv4,
		UUIDv6:           s.creds.UUIDv6,
		TrojanV4:         s.creds.TrojanV4,
		TrojanV6:         s.creds.TrojanV6,
		Paths: map[string]string{
			"xh": getEnv("BERMUDA_PATH_XH", "/api/v1/sync"),
			"ws": getEnv("BERMUDA_PATH_WS", "/api/v1/live"),
			"tr": getEnv("BERMUDA_PATH_TR", "/api/v1/gateway"),
		},
		Ports:     portsCopy,
		CreatedAt: time.Now().Unix(),
	}

	var bmbToken string
	if rawJSON, err := json.Marshal(payload); err == nil {
		bmbToken = "BMB1." + base64.RawURLEncoding.EncodeToString(rawJSON)
	}

	log.Println("[Supervisor] ========================================================================")
	log.Println("[Supervisor] ⚡ BERMUDA PORTAL ZERO-TOUCH PROVISIONING TERMINAL")
	if cfDom != "" {
		log.Printf("[Supervisor] » Cloudflare Portal Link : %s", buildPortalURL(cfDom, s.creds.MasterKey))
	}
	if lcDom != "" {
		log.Printf("[Supervisor] » Lucity Portal Link     : %s", buildPortalURL(lcDom, s.creds.MasterKey))
	}
	if cfDom == "" && lcDom == "" {
		log.Printf("[Supervisor] » Direct Portal Link     : %s", buildPortalURL(activeDom, s.creds.MasterKey))
	}
	if bmbToken != "" {
		log.Printf("[Supervisor] » Instant Portal Token   : %s", bmbToken)
	}
	log.Printf("[Supervisor] » Master Key             : %s", s.creds.MasterKey)
	log.Printf("[Supervisor] » Active IPv4 UUID       : %s", s.creds.UUIDv4)
	log.Printf("[Supervisor] » Active IPv6 UUID       : %s", s.creds.UUIDv6)
	log.Println("[Supervisor] Open the Portal Link or paste the BMB1 Token directly into index.html.")
	log.Println("[Supervisor] ========================================================================")
}

func (s *Supervisor) IsRunning() bool             { return s.state.Load()&healthRunning != 0 }
func (s *Supervisor) IsReady() bool               { return s.state.Load()&healthReady != 0 }
func (s *Supervisor) Restarts() int32             { return s.restarts.Load() }
func (s *Supervisor) RunStarted() <-chan struct{} { return s.runReady }

func (s *Supervisor) childEnv() []string {
	repl := map[string]string{
		"XRAY_LOCATION_ASSET": s.assetDir,
		"GOMEMLIMIT":          fmt.Sprintf("%dMiB", s.memLimitMB),
		"GODEBUG":             mergeCSVEnv(getEnv("GODEBUG", ""), "madvdontneed=1"),
		"GOGC":                "100",
	}
	if s.maxProcs > 0 {
		repl["GOMAXPROCS"] = strconv.Itoa(s.maxProcs)
	}
	return replaceEnv(os.Environ(), repl)
}

func resolveWorkingDir() string {
	if info, err := os.Stat("/app"); err == nil && info.IsDir() {
		return "/app"
	}
	if wd, err := os.Getwd(); err == nil && wd != "" {
		return wd
	}
	return "/"
}

func (s *Supervisor) Preflight() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return s.PreflightContext(ctx)
}

func (s *Supervisor) PreflightContext(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, 10*time.Second)
	defer cancel()

	if s.reaper == nil {
		return errors.New("reaper subsystem not initialized")
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create preflight pipe: %w", err)
	}
	defer pipeR.Close()

	attr := &os.ProcAttr{
		Dir:   resolveWorkingDir(),
		Env:   replaceEnv(os.Environ(), map[string]string{"XRAY_LOCATION_ASSET": s.assetDir}),
		Files: []*os.File{nil, pipeW, pipeW},
		Sys: &syscall.SysProcAttr{
			Setpgid: true,
		},
	}

	args := []string{s.binPath, "run", "-test", "-c", s.configPath}
	proc, exitCh, err := s.reaper.StartProcess(s.binPath, args, attr)
	_ = pipeW.Close()
	if err != nil {
		return fmt.Errorf("start preflight validator: %w", err)
	}

	var outBuf bytes.Buffer
	readDone := make(chan struct{})
	go func() {
		_, _ = io.Copy(&outBuf, pipeR)
		close(readDone)
	}()

	var exit childExit
	select {
	case exit = <-exitCh:
	case <-ctx.Done():
		_ = syscall.Kill(-proc.Pid, syscall.SIGKILL)
		exit = <-exitCh
		<-readDone
		_ = proc.Release()
		return fmt.Errorf("preflight check timed out: %w", ctx.Err())
	}

	<-readDone
	_ = proc.Release()

	if exit.status.ExitStatus() != 0 {
		return fmt.Errorf("preflight validation failed (code %d): %s",
			exit.status.ExitStatus(), strings.TrimSpace(outBuf.String()))
	}
	log.Printf("[Supervisor] Engine preflight validation passed for %s", s.configPath)
	return nil
}

func (s *Supervisor) Run(parent context.Context) error {
	s.mu.Lock()
	if !s.runStarted.CompareAndSwap(false, true) {
		s.mu.Unlock()
		return errors.New("supervisor Run may only be called once")
	}
	runCtx, cancel := context.WithCancel(parent)
	s.runCancel = cancel
	close(s.runReady)
	s.mu.Unlock()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	defer func() {
		cancel()
		s.mu.Lock()
		s.runCancel = nil
		s.mu.Unlock()
		close(s.stopped)
	}()

	backoff := initialBackoff
	for {
		if s.stopRequested.Load() || runCtx.Err() != nil {
			return nil
		}

		err := s.startAndWait(runCtx)
		if s.stopRequested.Load() || runCtx.Err() != nil {
			return nil
		}

		s.restarts.Add(1)
		s.mu.Lock()
		uptime := s.lastUptime
		s.mu.Unlock()
		if uptime >= stableWindow {
			backoff = initialBackoff
		}
		if err == nil {
			err = errors.New("engine worker exited normally")
		}

		delay := jitteredBackoff(backoff)
		log.Printf("[Supervisor] Engine worker stopped after %s (err: %v); restart=%d in %s",
			uptime.Round(time.Millisecond), err, s.restarts.Load(), delay.Round(time.Millisecond))

		timer := time.NewTimer(delay)
		select {
		case <-runCtx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil
		case <-timer.C:
		}
		backoff *= 2
		if backoff > maxBackoffInterval {
			backoff = maxBackoffInterval
		}
	}
}

func jitteredBackoff(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	spread := float64(base) * backoffJitterFrac
	delta := (mrand.Float64()*2 - 1) * spread
	result := time.Duration(float64(base) + delta)
	if result < 0 {
		return 0
	}
	return result
}

func (s *Supervisor) startAndWait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if s.reaper == nil {
		return errors.New("reaper subsystem not initialized")
	}
	s.mu.Lock()
	s.lastUptime = 0
	s.mu.Unlock()

	stdoutR, stdoutW, err := os.Pipe()
	if err != nil {
		return fmt.Errorf("create stdout pipe: %w", err)
	}
	stderrR, stderrW, err := os.Pipe()
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		return fmt.Errorf("create stderr pipe: %w", err)
	}

	attr := &os.ProcAttr{
		Dir:   resolveWorkingDir(),
		Env:   s.childEnv(),
		Files: []*os.File{nil, stdoutW, stderrW},
		Sys: &syscall.SysProcAttr{
			Setpgid:   true,
			Pdeathsig: syscall.SIGKILL,
		},
	}

	args := []string{s.binPath, "run", "-c", s.configPath}
	proc, exitCh, err := s.reaper.StartProcess(s.binPath, args, attr)
	if err != nil {
		_ = stdoutR.Close()
		_ = stdoutW.Close()
		_ = stderrR.Close()
		_ = stderrW.Close()
		return fmt.Errorf("start engine worker: %w", err)
	}

	_ = stdoutW.Close()
	_ = stderrW.Close()

	generation := s.startGeneration()
	s.mu.Lock()
	s.proc = proc
	s.startedAt = time.Now()
	s.lastUptime = 0
	s.mu.Unlock()
	pid := proc.Pid
	log.Printf("[Supervisor] Engine worker active pid=%d pgid=%d GOMEMLIMIT=%dMiB GOMAXPROCS=%d",
		pid, pid, s.memLimitMB, s.maxProcs)

	var pumpWG sync.WaitGroup
	pumpWG.Add(2)
	go func() { defer pumpWG.Done(); s.pumpPipe(stdoutR, "[Engine-Out]") }()
	go func() { defer pumpWG.Done(); s.pumpPipe(stderrR, "[Engine-Err]") }()
	pumpDone := make(chan struct{})
	go func() { pumpWG.Wait(); close(pumpDone) }()

	probeCtx, cancelProbes := context.WithCancel(ctx)
	probeDone := make(chan struct{})
	go func() {
		defer close(probeDone)
		s.awaitReadiness(probeCtx, generation)
	}()

	var exit childExit
	select {
	case exit = <-exitCh:
		terminateProcessGroup(pid, 200*time.Millisecond)
	case <-ctx.Done():
		terminateProcessGroup(pid, s.terminationGrace())
		exit = <-exitCh
	}

	cancelProbes()
	<-probeDone
	s.endGeneration(generation)

	s.mu.Lock()
	s.lastUptime = time.Since(s.startedAt)
	if s.proc == proc {
		s.proc = nil
	}
	s.mu.Unlock()
	_ = proc.Release()

	select {
	case <-pumpDone:
	case <-time.After(1500 * time.Millisecond):
		_ = stdoutR.Close()
		_ = stderrR.Close()
	}
	_ = stdoutR.Close()
	_ = stderrR.Close()

	if ctx.Err() != nil || s.stopRequested.Load() {
		log.Printf("[Supervisor] Engine worker pid=%d stopped cleanly", pid)
		return nil
	}
	if exit.status.ExitStatus() != 0 {
		return fmt.Errorf("engine worker pid=%d exited with status %d", pid, exit.status.ExitStatus())
	}
	return fmt.Errorf("engine worker pid=%d exited normally", pid)
}

func (s *Supervisor) startGeneration() uint64 {
	for {
		old := s.state.Load()
		gen := (old >> healthGenShift) + 1
		next := (gen << healthGenShift) | healthRunning
		if s.state.CompareAndSwap(old, next) {
			return gen
		}
	}
}

func (s *Supervisor) endGeneration(generation uint64) {
	for {
		old := s.state.Load()
		if old>>healthGenShift != generation {
			return
		}
		next := (generation + 1) << healthGenShift
		if s.state.CompareAndSwap(old, next) {
			return
		}
	}
}

func (s *Supervisor) commitProbe(generation uint64, xh, ws, tr bool) bool {
	var flags uint64 = healthRunning
	if xh {
		flags |= healthXH
	}
	if ws {
		flags |= healthWS
	}
	if tr {
		flags |= healthTR
	}
	if xh && ws && tr {
		flags |= healthReady
	}
	for {
		old := s.state.Load()
		if old>>healthGenShift != generation || old&healthRunning == 0 {
			return false
		}
		if s.state.CompareAndSwap(old, (generation<<healthGenShift)|flags) {
			s.lastProbeNS.Store(time.Now().UnixNano())
			return true
		}
	}
}

func (s *Supervisor) pumpPipe(r io.Reader, prefix string) {
	reader := scannerBufPool.Get().(*bufio.Reader)
	reader.Reset(r)
	defer func() {
		reader.Reset(nil)
		scannerBufPool.Put(reader)
	}()

	for {
		fragment, err := reader.ReadSlice('\n')
		if len(fragment) != 0 {
			writePumpRecord(os.Stderr, prefix, fragment)
		}
		if err == nil || errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if errors.Is(err, io.EOF) {
			return
		}
		writePumpRecord(os.Stderr, prefix, []byte("log pipe read error: "+err.Error()))
		return
	}
}

func writePumpRecord(dst *os.File, prefix string, data []byte) {
	pumpLogMu.Lock()
	defer pumpLogMu.Unlock()

	now := time.Now().UTC()
	var header [256]byte
	year := now.Year()
	header[0] = byte('0' + year/1000%10)
	header[1] = byte('0' + year/100%10)
	header[2] = byte('0' + year/10%10)
	header[3] = byte('0' + year%10)
	header[4] = '/'
	putTwoDigits(header[5:7], int(now.Month()))
	header[7] = '/'
	putTwoDigits(header[8:10], now.Day())
	header[10] = ' '
	putTwoDigits(header[11:13], now.Hour())
	header[13] = ':'
	putTwoDigits(header[14:16], now.Minute())
	header[16] = ':'
	putTwoDigits(header[17:19], now.Second())
	header[19] = ' '
	pos := 20 + copy(header[20:len(header)-1], prefix)
	header[pos] = ' '
	writeFileAll(dst, header[:pos+1])
	writeFileAll(dst, data)
	if len(data) == 0 || data[len(data)-1] != '\n' {
		writeFileAll(dst, pumpNewline[:])
	}
}

func putTwoDigits(dst []byte, value int) {
	dst[0] = byte('0' + value/10%10)
	dst[1] = byte('0' + value%10)
}

func writeFileAll(dst *os.File, data []byte) {
	for len(data) != 0 {
		n, err := dst.Write(data)
		if n > 0 {
			data = data[n:]
		}
		if err != nil || n == 0 {
			return
		}
	}
}

func (s *Supervisor) awaitReadiness(ctx context.Context, generation uint64) {
	started := time.Now()
	deadline := started.Add(s.startTimeout)
	var warned bool
	nextDelay := time.Duration(0)

	for {
		state := s.state.Load()
		if state>>healthGenShift != generation || state&healthRunning == 0 {
			return
		}
		if nextDelay > 0 {
			timer := time.NewTimer(nextDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
		}
		if ctx.Err() != nil {
			return
		}

		prior := s.state.Load()
		xh, ws, tr := s.probeAll(ctx, generation)
		isAllOk := xh && ws && tr

		if s.commitProbe(generation, xh, ws, tr) && isAllOk && prior&healthReady == 0 {
			log.Printf("[Supervisor] All engine inbounds ready after %s", time.Since(started).Round(time.Millisecond))
			s.LogProvisioningLink("")
		}
		if !warned && !isAllOk && time.Now().After(deadline) {
			warned = true
			log.Printf("[Supervisor] Engine readiness pending after %s; continuing background probes", s.startTimeout)
		}

		if time.Since(started) < fastProbeWindow {
			nextDelay = fastProbeInterval
		} else if isAllOk {
			nextDelay = slowProbeInterval
		} else {
			nextDelay = degradedProbeInterval
		}
	}
}

func (s *Supervisor) probeAll(ctx context.Context, generation uint64) (bool, bool, bool) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	state := s.state.Load()
	if ctx.Err() != nil || state>>healthGenShift != generation || state&healthRunning == 0 {
		return false, false, false
	}

	results := make(chan struct {
		index int
		ok    bool
	}, 3)
	addresses := [3]string{s.xhAddr, s.wsAddr, s.trAddr}
	for i, address := range addresses {
		go func(index int, addr string) {
			results <- struct {
				index int
				ok    bool
			}{index: index, ok: s.probeTCP(ctx, addr)}
		}(i, address)
	}
	var status [3]bool
	for range addresses {
		select {
		case result := <-results:
			status[result.index] = result.ok
		case <-ctx.Done():
			return false, false, false
		}
	}
	return status[0], status[1], status[2]
}

func (s *Supervisor) probeTCP(parent context.Context, addr string) bool {
	ctx, cancel := context.WithTimeout(parent, probeDialTimeout)
	defer cancel()
	conn, err := s.probeDialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *Supervisor) ProbeNow() (bool, bool, bool) {
	state := s.state.Load()
	if state&healthRunning == 0 {
		return false, false, false
	}

	last := s.lastProbeNS.Load()
	if last != 0 && (time.Now().UnixNano()-last) < int64(minProbeNowInterval) {
		return state&healthXH != 0, state&healthWS != 0, state&healthTR != 0
	}

	generation := state >> healthGenShift
	xh, ws, tr := s.probeAll(context.Background(), generation)
	if !s.commitProbe(generation, xh, ws, tr) {
		return false, false, false
	}
	return xh, ws, tr
}

func (s *Supervisor) Snapshot() SupervisorHealthSnapshot {
	state := s.state.Load()
	s.mu.Lock()
	started := s.startedAt
	pid := 0
	if s.proc != nil {
		pid = s.proc.Pid
	}
	s.mu.Unlock()

	var uptime int64
	if state&healthRunning != 0 && !started.IsZero() {
		uptime = int64(time.Since(started).Seconds())
	}
	lastProbeAt := ""
	if probedAt := s.lastProbeNS.Load(); probedAt != 0 {
		lastProbeAt = time.Unix(0, probedAt).UTC().Format(time.RFC3339Nano)
	}
	return SupervisorHealthSnapshot{
		Running:     state&healthRunning != 0,
		Ready:       state&healthReady != 0,
		Restarts:    s.restarts.Load(),
		UptimeSec:   uptime,
		XHInbound:   state&healthXH != 0,
		WSInbound:   state&healthWS != 0,
		TRInbound:   state&healthTR != 0,
		LastProbeAt: lastProbeAt,
		ChildPID:    pid,
	}
}

func (s *Supervisor) Stop(grace time.Duration) {
	if grace <= 0 {
		grace = s.stopTimeout
	}
	s.stopGraceNS.Store(int64(grace))
	s.stopRequested.Store(true)
	s.mu.Lock()
	cancel := s.runCancel
	running := s.runStarted.Load()
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if running {
		select {
		case <-s.stopped:
		case <-time.After(grace + 2*time.Second):
			log.Printf("[Supervisor] Warning: Stop deadline exceeded (%s); unblocking caller", grace+2*time.Second)
		}
	}
}

func (s *Supervisor) terminationGrace() time.Duration {
	n := s.stopGraceNS.Load()
	if n <= 0 {
		return s.stopTimeout
	}
	return time.Duration(n)
}

func terminateProcessGroup(pgid int, grace time.Duration) {
	if pgid <= 1 {
		return
	}
	if err := syscall.Kill(-pgid, syscall.SIGTERM); err != nil && !errors.Is(err, syscall.ESRCH) {
		log.Printf("[Supervisor] SIGTERM process group %d: %v", pgid, err)
	}
	deadline := time.Now().Add(grace)
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Kill(-pgid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if !time.Now().Before(deadline) {
			log.Printf("[Supervisor] Process group %d exceeded TERM grace; escalating to SIGKILL", pgid)
			if killErr := syscall.Kill(-pgid, syscall.SIGKILL); killErr != nil && !errors.Is(killErr, syscall.ESRCH) {
				log.Printf("[Supervisor] SIGKILL process group %d: %v", pgid, killErr)
			}
			return
		}
		<-ticker.C
	}
}

func replaceEnv(env []string, replacements map[string]string) []string {
	out := make([]string, 0, len(env)+len(replacements))
	seen := make(map[string]struct{}, len(replacements))
	for _, item := range env {
		key, _, ok := strings.Cut(item, "=")
		if !ok {
			out = append(out, item)
			continue
		}
		if value, replace := replacements[key]; replace {
			if _, already := seen[key]; !already {
				out = append(out, key+"="+value)
				seen[key] = struct{}{}
			}
			continue
		}
		out = append(out, item)
	}
	for key, value := range replacements {
		if _, ok := seen[key]; !ok {
			out = append(out, key+"="+value)
		}
	}
	return out
}

func mergeCSVEnv(existing, required string) string {
	key, _, _ := strings.Cut(required, "=")
	parts := strings.Split(existing, ",")
	kept := parts[:0]
	for _, part := range parts {
		part = strings.TrimSpace(part)
		partKey, _, _ := strings.Cut(part, "=")
		if partKey != key && part != "" {
			kept = append(kept, part)
		}
	}
	kept = append(kept, required)
	return strings.Join(kept, ",")
}

func getEnvInt(key string, fallback int) int {
	if v, ok := syscall.Getenv(key); ok {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			if n, err := strconv.Atoi(trimmed); err == nil && n > 0 {
				return n
			}
		}
	}
	return fallback
}

func getEnv(key, fallback string) string {
	if value, ok := syscall.Getenv(key); ok {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return fallback
}
