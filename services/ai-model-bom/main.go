package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------- metrics ----------

var (
	metricGenerated atomic.Int64
	metricVerified  atomic.Int64
	metricDiffs     atomic.Int64
	metricHTTPReqs  atomic.Int64
)

// ---------- config ----------

// ServiceConfig is the top-level configuration.
type ServiceConfig struct {
	Version        int      `yaml:"version"`
	RequiredFields []string `yaml:"required_fields"`
	Daemon         struct {
		BindAddr     string   `yaml:"bind_addr"`
		AllowedPaths []string `yaml:"allowed_paths"`
		ReadTimeout  int      `yaml:"read_timeout_seconds"`
		WriteTimeout int      `yaml:"write_timeout_seconds"`
	} `yaml:"daemon"`
	PrivacyProfile *PrivacyProfile `yaml:"privacy_profile,omitempty"`
}

// ---------- main ----------

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "generate":
		cmdGenerate(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "diff":
		cmdDiff(os.Args[2:])
	case "attest":
		cmdAttest(os.Args[2:])
	case "evaluate":
		cmdEvaluate(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "keygen":
		cmdKeygen(os.Args[2:])
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `ai-model-bom — AI/ML BOM generator, verifier, and attestation companion

Usage:
  ai-model-bom <command> [flags]

Commands:
  generate   Generate BOM from a model file or directory
  verify     Verify a signed BOM
  diff       Compare two BOMs
  attest     Create a signed attestation
  evaluate   Check deployment readiness
  serve      Run as HTTP daemon
  keygen     Generate Ed25519 keypair

Run "ai-model-bom <command> --help" for command-specific flags.

Environment:
  AIMBOM_CONFIG   Path to config YAML (default: policies/default-policy.yaml)
  SERVICE_TOKEN   Bearer token for protected endpoints
  SIGNING_KEY     Base64-encoded Ed25519 private key
  VERIFY_KEY      Base64-encoded Ed25519 public key (for verify command)
`)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func loadSigningKey() ed25519.PrivateKey {
	keyStr := os.Getenv("SIGNING_KEY")
	if keyStr == "" {
		return nil
	}
	data, err := base64.StdEncoding.DecodeString(keyStr)
	if err != nil || len(data) != ed25519.PrivateKeySize {
		return nil
	}
	return ed25519.PrivateKey(data)
}

func loadConfig(configPath string) *ServiceConfig {
	if configPath == "" {
		configPath = envOr("AIMBOM_CONFIG", "policies/default-policy.yaml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return &ServiceConfig{Version: 1}
	}

	var cfg ServiceConfig
	yaml.Unmarshal(data, &cfg)
	return &cfg
}

// ---------- CLI commands ----------

func cmdGenerate(args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	metaFile := fs.String("meta", "", "Path to metadata YAML file")
	outFile := fs.String("out", "", "Output file path (default: stdout)")
	evidenceFile := fs.String("evidence", "", "Path to evidence JSON file to attach")
	evidenceComp := fs.String("evidence-component", "", "Component bom-ref or name to attach evidence to")
	privacyFlag := fs.String("privacy-profile", "", "Privacy profile: none, default, or path to YAML")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom generate PATH [flags]\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	modelPath := fs.Arg(0)

	// Load metadata if provided
	var meta *ModelMetadata
	if *metaFile != "" {
		data, err := os.ReadFile(*metaFile)
		if err != nil {
			log.Fatalf("read metadata: %v", err)
		}
		meta = &ModelMetadata{}
		if err := yaml.Unmarshal(data, meta); err != nil {
			log.Fatalf("parse metadata: %v", err)
		}
		// Validate metadata
		if issues := ValidateMetadata(meta); len(issues) > 0 {
			for _, iss := range issues {
				log.Printf("metadata %s: %s: %s", iss.Severity, iss.Field, iss.Message)
			}
			hasError := false
			for _, iss := range issues {
				if iss.Severity == "error" {
					hasError = true
				}
			}
			if hasError {
				log.Fatal("metadata validation failed with errors")
			}
		}
	}

	bom, err := GenerateBOM(modelPath, meta)
	if err != nil {
		log.Fatalf("generate BOM: %v", err)
	}

	// Attach evidence if provided
	if *evidenceFile != "" {
		items, err := ImportEvidence(*evidenceFile)
		if err != nil {
			log.Fatalf("import evidence: %v", err)
		}
		targetRef := *evidenceComp
		if targetRef == "" && len(bom.Components) > 0 {
			targetRef = bom.Components[0].BOMRef
		}
		if !AttachEvidence(bom, targetRef, items) {
			log.Fatalf("component not found: %s", targetRef)
		}
	}

	// Apply privacy redaction if requested
	if *privacyFlag != "" {
		profile := resolvePrivacyProfile(*privacyFlag)
		bom = RedactBOM(bom, profile)
	}

	// Validate generated BOM
	if issues := ValidateBOM(bom); len(issues) > 0 {
		for _, iss := range issues {
			if iss.Severity == "error" {
				log.Printf("BOM validation %s: %s: %s", iss.Severity, iss.Field, iss.Message)
			}
		}
	}

	privKey := loadSigningKey()

	var output interface{}
	if privKey != nil {
		output = SignBOM(bom, privKey, "ai-model-bom")
	} else {
		output = bom
	}

	metricGenerated.Add(1)

	if *outFile != "" {
		data, _ := json.MarshalIndent(output, "", "  ")
		if err := os.WriteFile(*outFile, data, 0o644); err != nil {
			log.Fatalf("write output: %v", err)
		}
		fmt.Printf("BOM written to %s (%d components)\n", *outFile, len(bom.Components))
	} else {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(output)
	}
}

func cmdVerify(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom verify FILE\n\nVerify a signed BOM's integrity and signature.\nSet VERIFY_KEY env to base64-encoded Ed25519 public key.\n")
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	data, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		log.Fatalf("read BOM: %v", err)
	}

	var sb SignedBOM
	if err := json.Unmarshal(data, &sb); err != nil {
		log.Fatalf("parse signed BOM: %v", err)
	}

	if sb.Signature == "" {
		fmt.Println("BOM is not signed")
		os.Exit(1)
	}

	pubKeyStr := os.Getenv("VERIFY_KEY")
	if pubKeyStr == "" {
		log.Fatal("set VERIFY_KEY env to base64 public key")
	}
	pubKeyData, err := base64.StdEncoding.DecodeString(pubKeyStr)
	if err != nil {
		log.Fatalf("decode public key: %v", err)
	}

	valid, reason := VerifySignedBOM(sb, ed25519.PublicKey(pubKeyData))
	metricVerified.Add(1)

	if valid {
		fmt.Printf("VALID: BOM signature verified (signed_at=%s signed_by=%s)\n", sb.SignedAt, sb.SignedBy)
		fmt.Printf("  components: %d\n", len(sb.BOM.Components))
	} else {
		fmt.Printf("INVALID: %s\n", reason)
		os.Exit(2)
	}
}

func cmdDiff(args []string) {
	fs := flag.NewFlagSet("diff", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom diff OLD NEW\n\nCompare two BOMs and report trust-relevant changes.\n")
	}
	fs.Parse(args)

	if fs.NArg() < 2 {
		fs.Usage()
		os.Exit(1)
	}

	oldBOM := loadBOMFile(fs.Arg(0))
	newBOM := loadBOMFile(fs.Arg(1))

	result := DiffBOMs(oldBOM, newBOM)
	metricDiffs.Add(1)

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(result)

	if result.TrustRelevant {
		os.Exit(1)
	}
}

func cmdAttest(args []string) {
	fs := flag.NewFlagSet("attest", flag.ExitOnError)
	subject := fs.String("subject", "", "Subject (model name or hash)")
	predicate := fs.String("predicate", "deployment-ready", "Predicate being attested")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom attest BOM [flags]\n\nCreate a signed attestation for a model BOM.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	bom := loadBOMFile(fs.Arg(0))

	if *subject == "" && len(bom.Components) > 0 {
		*subject = bom.Components[0].Name
	}

	// Collect evidence from BOM components
	var evidence []EvidenceItem
	for _, comp := range bom.Components {
		evidence = append(evidence, comp.Evidence...)
	}

	att := CreateAttestation(*subject, *predicate, "ai-model-bom", evidence)

	privKey := loadSigningKey()
	if privKey != nil {
		SignAttestation(&att, privKey)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(att)
}

func cmdEvaluate(args []string) {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	configFile := fs.String("config", "", "Path to config YAML")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom evaluate BOM [flags]\n\nCheck if a BOM meets deployment readiness criteria.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(1)
	}

	bom := loadBOMFile(fs.Arg(0))
	cfg := loadConfig(*configFile)

	fields := cfg.RequiredFields
	if len(fields) == 0 {
		fields = []string{"hash", "license", "model_card"}
	}

	ready, missing := EvaluateReadiness(bom, fields)

	if ready {
		fmt.Println("READY: all required fields present")
	} else {
		fmt.Println("NOT READY: missing required fields:")
		for _, m := range missing {
			fmt.Printf("  - %s\n", m)
		}
		os.Exit(2)
	}
}

// ---------- HTTP daemon ----------

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	configFile := fs.String("config", "", "Path to config YAML")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom serve [flags]\n\nRun as an HTTP daemon.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	cfg := loadConfig(*configFile)
	privKey := loadSigningKey()
	token := os.Getenv("SERVICE_TOKEN")

	mux := buildMux(cfg, privKey, token)

	addr := cfg.Daemon.BindAddr
	if addr == "" {
		addr = "127.0.0.1:8515"
	}

	readTimeout := cfg.Daemon.ReadTimeout
	if readTimeout <= 0 {
		readTimeout = 30
	}
	writeTimeout := cfg.Daemon.WriteTimeout
	if writeTimeout <= 0 {
		writeTimeout = 60
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  time.Duration(readTimeout) * time.Second,
		WriteTimeout: time.Duration(writeTimeout) * time.Second,
	}

	log.Printf("ai-model-bom serving on %s", addr)
	log.Fatal(srv.ListenAndServe())
}

// buildMux constructs the HTTP handler. Exported for testing.
func buildMux(cfg *ServiceConfig, privKey ed25519.PrivateKey, token string) *http.ServeMux {
	mux := http.NewServeMux()

	// ---------- unauthenticated ----------

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	// ---------- authenticated endpoints ----------

	mux.HandleFunc("/v1/generate", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Path     string         `json:"path"`
			Metadata *ModelMetadata `json:"metadata,omitempty"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		// Validate path against allowlist
		if !isPathAllowed(req.Path, cfg.Daemon.AllowedPaths) {
			http.Error(w, `{"error":"path not in allowed_paths"}`, http.StatusForbidden)
			return
		}

		// Validate metadata
		if req.Metadata != nil {
			if issues := ValidateMetadata(req.Metadata); len(issues) > 0 {
				for _, iss := range issues {
					if iss.Severity == "error" {
						http.Error(w, fmt.Sprintf(`{"error":"metadata validation: %s"}`, iss.Message), http.StatusBadRequest)
						return
					}
				}
			}
		}

		bom, err := GenerateBOM(req.Path, req.Metadata)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":%q}`, err.Error()), http.StatusBadRequest)
			return
		}

		metricGenerated.Add(1)

		resp := map[string]interface{}{"bom": bom}
		if privKey != nil {
			resp["signed_bom"] = SignBOM(bom, privKey, "ai-model-bom")
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	})

	mux.HandleFunc("/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var sb SignedBOM
		if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&sb); err != nil {
			http.Error(w, `{"error":"invalid signed BOM"}`, http.StatusBadRequest)
			return
		}

		metricVerified.Add(1)

		if privKey != nil {
			pubKey := privKey.Public().(ed25519.PublicKey)
			valid, reason := VerifySignedBOM(sb, pubKey)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"valid": valid, "reason": reason,
			})
		} else {
			http.Error(w, `{"error":"no signing key configured for verification"}`, http.StatusServiceUnavailable)
		}
	})

	mux.HandleFunc("/v1/diff", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Old *ModelBOM `json:"old"`
			New *ModelBOM `json:"new"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 20<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		if req.Old == nil || req.New == nil {
			http.Error(w, `{"error":"both old and new BOMs required"}`, http.StatusBadRequest)
			return
		}

		result := DiffBOMs(req.Old, req.New)
		metricDiffs.Add(1)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})

	mux.HandleFunc("/v1/evaluate", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var bom ModelBOM
		if err := json.NewDecoder(io.LimitReader(r.Body, 10<<20)).Decode(&bom); err != nil {
			http.Error(w, `{"error":"invalid BOM"}`, http.StatusBadRequest)
			return
		}

		fields := cfg.RequiredFields
		if len(fields) == 0 {
			fields = []string{"hash", "license", "model_card"}
		}

		ready, missing := EvaluateReadiness(&bom, fields)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ready":   ready,
			"missing": missing,
		})
	})

	mux.HandleFunc("/v1/attest", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Subject   string         `json:"subject"`
			Predicate string         `json:"predicate"`
			Evidence  []EvidenceItem `json:"evidence"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"invalid request"}`, http.StatusBadRequest)
			return
		}

		att := CreateAttestation(req.Subject, req.Predicate, "ai-model-bom", req.Evidence)
		if privKey != nil {
			SignAttestation(&att, privKey)
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(att)
	})

	mux.HandleFunc("/v1/metrics", func(w http.ResponseWriter, r *http.Request) {
		metricHTTPReqs.Add(1)
		if !checkToken(r, token) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]int64{
			"generated_total":     metricGenerated.Load(),
			"verified_total":      metricVerified.Load(),
			"diffs_total":         metricDiffs.Load(),
			"http_requests_total": metricHTTPReqs.Load(),
		})
	})

	return mux
}

func cmdKeygen(args []string) {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	prefix := fs.String("out", "ai-model-bom", "Output filename prefix")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: ai-model-bom keygen [flags]\n\nGenerate an Ed25519 keypair for BOM signing.\n\nFlags:\n")
		fs.PrintDefaults()
	}
	fs.Parse(args)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("keygen failed: %v", err)
	}

	privB64 := base64.StdEncoding.EncodeToString(priv)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	os.WriteFile(*prefix+".key", []byte(privB64+"\n"), 0o600)
	os.WriteFile(*prefix+".pub", []byte(pubB64+"\n"), 0o644)

	fmt.Printf("Keys written: %s.key (private), %s.pub (public)\n", *prefix, *prefix)
}

// ---------- helpers ----------

func checkToken(r *http.Request, expected string) bool {
	if expected == "" {
		return true
	}
	auth := r.Header.Get("Authorization")
	provided := strings.TrimPrefix(auth, "Bearer ")
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func loadBOMFile(path string) *ModelBOM {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read BOM: %v", err)
	}

	// Try SignedBOM first
	var sb SignedBOM
	if err := json.Unmarshal(data, &sb); err == nil && sb.BOM != nil {
		return sb.BOM
	}

	var bom ModelBOM
	if err := json.Unmarshal(data, &bom); err != nil {
		log.Fatalf("parse BOM: %v", err)
	}
	return &bom
}

// isPathAllowed checks if a path is under one of the allowed root directories.
// An empty allowlist permits all paths (backwards compatibility).
func isPathAllowed(path string, allowedPaths []string) bool {
	if len(allowedPaths) == 0 {
		return true
	}

	absPath, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	// Resolve symlinks in the resolved path
	absPath, err = filepath.EvalSymlinks(absPath)
	if err != nil {
		return false
	}

	for _, allowed := range allowedPaths {
		allowedAbs, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		allowedAbs, err = filepath.EvalSymlinks(allowedAbs)
		if err != nil {
			continue
		}
		// Ensure it's a clean prefix check with path separator
		if absPath == allowedAbs || strings.HasPrefix(absPath, allowedAbs+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// resolvePrivacyProfile returns a PrivacyProfile from a flag value.
func resolvePrivacyProfile(value string) PrivacyProfile {
	switch strings.ToLower(value) {
	case "none":
		return PrivacyProfile{}
	case "default":
		return DefaultPrivacyProfile()
	default:
		// Try loading from YAML file
		data, err := os.ReadFile(value)
		if err != nil {
			log.Printf("warning: could not read privacy profile %s, using default", value)
			return DefaultPrivacyProfile()
		}
		var profile PrivacyProfile
		if err := yaml.Unmarshal(data, &profile); err != nil {
			log.Printf("warning: could not parse privacy profile %s, using default", value)
			return DefaultPrivacyProfile()
		}
		return profile
	}
}
