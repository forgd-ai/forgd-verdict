// gitleaksd keeps one gitleaks detector alive and scans over a Unix socket.
//
// The CLI recompiles ~170 regexes on every exec. That is 15 ms on a fast
// laptop core and 477 ms on an Azure Container Apps vCPU, measured, and it
// is a fixed cost: it does not shrink with body size, more cores do not help
// because the compile is single-threaded, and the session cache cannot
// amortize it because every frame pays it again. On the inference-hook path
// that fixed cost was the whole latency story.
//
// So: compile once at startup, then answer scan requests. Same rule set,
// same config file, same findings -- only the process boundary moves.
//
// A Unix socket rather than a TCP port: the secret being scanned crosses
// this boundary, and a socket carries filesystem permissions and cannot be
// reached from off-box by a misconfigured ingress. It replaces a temp file
// on disk, which is what the CLI path used, so it is strictly less exposed.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
)

// Findings are reported in the same shape the CLI's JSON report uses, so the
// Python side reads one format regardless of which transport served it.
type finding struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	Secret      string  `json:"Secret"`
	Match       string  `json:"Match"`
	StartLine   int     `json:"StartLine"`
	EndLine     int     `json:"EndLine"`
	StartColumn int     `json:"StartColumn"`
	EndColumn   int     `json:"EndColumn"`
	Entropy     float32 `json:"Entropy"`
}

func loadConfig(path string) (config.Config, error) {
	v := viper.New()
	if path == "" {
		// Mirrors `--config` being mandatory on the CLI path: refuse rather
		// than fall back to a config the scanned content could influence.
		return config.Config{}, fmt.Errorf("a --config path is required")
	}
	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		return config.Config{}, fmt.Errorf("reading %s: %w", path, err)
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return config.Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return vc.Translate()
}

func main() {
	socket := flag.String("socket", "/run/forgd/gitleaksd.sock", "unix socket to listen on")
	cfgPath := flag.String("config", "", "gitleaks config TOML (required)")
	flag.Parse()

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("gitleaksd: %v", err)
	}
	detector := detect.NewDetector(cfg)
	// The scanned content is untrusted and may carry a gitleaks:allow
	// comment. The CLI path passes --ignore-gitleaks-allow for that reason;
	// this is the same decision.
	detector.IgnoreGitleaksAllow = true

	if err := os.MkdirAll(filepathDir(*socket), 0o750); err != nil {
		log.Fatalf("gitleaksd: socket dir: %v", err)
	}
	// A stale socket from an unclean exit would make Listen fail.
	_ = os.Remove(*socket)

	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Fatalf("gitleaksd: listen: %v", err)
	}
	// Owner-only: the secret being scanned crosses this boundary.
	if err := os.Chmod(*socket, 0o600); err != nil {
		log.Fatalf("gitleaksd: chmod socket: %v", err)
	}
	defer os.Remove(*socket)

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","rules":%d}`, len(cfg.Rules))
	})
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read failed", http.StatusBadRequest)
			return
		}
		out := make([]finding, 0, 4)
		for _, f := range detector.DetectString(string(body)) {
			out = append(out, finding{
				RuleID:      f.RuleID,
				Description: f.Description,
				Secret:      f.Secret,
				Match:       f.Match,
				// The library is 0-based; the CLI's JSON report is 1-based,
				// and the Python line map is written against the CLI. Convert
				// here so one convention crosses the boundary regardless of
				// transport. A test asserts the two transports return
				// identical findings for identical input.
				StartLine:   f.StartLine + 1,
				EndLine:     f.EndLine + 1,
				StartColumn: f.StartColumn,
				EndColumn:   f.EndColumn,
				Entropy:     f.Entropy,
			})
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(out); err != nil {
			log.Printf("gitleaksd: encode: %v", err)
		}
	})

	srv := &http.Server{Handler: mux}
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
		<-sig
		_ = srv.Close()
	}()

	log.Printf("gitleaksd: ready on %s with %d rules", *socket, len(cfg.Rules))
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatalf("gitleaksd: serve: %v", err)
	}
}

// filepathDir avoids importing path/filepath for one call.
func filepathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			if i == 0 {
				return "/"
			}
			return p[:i]
		}
	}
	return "."
}
