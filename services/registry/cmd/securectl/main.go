package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"
)

var registryURL = "http://127.0.0.1:8470"
var apiClient = &http.Client{Timeout: 15 * time.Second}

func init() {
	if u := os.Getenv("REGISTRY_URL"); u != "" {
		registryURL = u
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `securectl - Secure AI Appliance model management CLI

Usage:
  securectl list                     List all models in the trusted registry
  securectl info <name>              Show details for a model
  securectl verify <name>            Verify a model's hash against manifest
  securectl path <name>              Print the filesystem path of a model
  securectl delete <name>            Remove a model from the registry
  securectl status                   Show registry service health

Environment:
  REGISTRY_URL         Registry endpoint (default: http://127.0.0.1:8470)
  SERVICE_TOKEN_PATH   Registry service token path (default: /run/secure-ai/service-token)
`)
	os.Exit(1)
}

func readServiceToken() string {
	tokenPath := os.Getenv("SERVICE_TOKEN_PATH")
	if tokenPath == "" {
		tokenPath = "/run/secure-ai/service-token"
	}
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func apiRequest(method, path string, body io.Reader) ([]byte, int, error) {
	req, err := http.NewRequest(method, registryURL+path, body)
	if err != nil {
		return nil, 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token := readServiceToken(); token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := apiClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return respBody, resp.StatusCode, nil
}

func apiGet(path string) ([]byte, int, error) {
	return apiRequest(http.MethodGet, path, nil)
}

func apiDelete(path string) ([]byte, int, error) {
	return apiRequest(http.MethodDelete, path, nil)
}

func apiPost(path string) ([]byte, int, error) {
	return apiRequest(http.MethodPost, path, strings.NewReader("{}"))
}

func modelQueryPath(endpoint, name string) string {
	values := url.Values{}
	values.Set("name", name)
	return endpoint + "?" + values.Encode()
}

func cmdList() {
	data, code, err := apiGet("/v1/models")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code != 200 {
		fmt.Fprintf(os.Stderr, "error: HTTP %d: %s\n", code, data)
		os.Exit(1)
	}

	var models []map[string]interface{}
	json.Unmarshal(data, &models)

	if len(models) == 0 {
		fmt.Println("No models in registry.")
		return
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tFORMAT\tSIZE\tSHA256\tPROMOTED")
	for _, m := range models {
		name, _ := m["name"].(string)
		format, _ := m["format"].(string)
		size, _ := m["size_bytes"].(float64)
		sha, _ := m["sha256"].(string)
		promoted, _ := m["promoted_at"].(string)

		sizeStr := formatBytes(int64(size))
		shortSha := sha
		if len(sha) > 12 {
			shortSha = sha[:12]
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", name, format, sizeStr, shortSha, promoted)
	}
	w.Flush()
}

func cmdInfo(name string) {
	data, code, err := apiGet(modelQueryPath("/v1/model", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}

	var pretty map[string]interface{}
	json.Unmarshal(data, &pretty)
	out, _ := json.MarshalIndent(pretty, "", "  ")
	fmt.Println(string(out))
}

func cmdVerify(name string) {
	data, code, err := apiPost(modelQueryPath("/v1/model/verify", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	var result map[string]string
	json.Unmarshal(data, &result)

	if code == 200 {
		fmt.Printf("VERIFIED: %s (sha256=%s)\n", name, result["sha256"])
	} else {
		fmt.Printf("FAILED: %s\n", name)
		fmt.Printf("  expected: %s\n", result["expected"])
		fmt.Printf("  actual:   %s\n", result["actual"])
		os.Exit(1)
	}
}

func cmdPath(name string) {
	data, code, err := apiGet(modelQueryPath("/v1/model/path", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}
	var result map[string]string
	json.Unmarshal(data, &result)
	fmt.Println(result["path"])
}

func cmdDelete(name string) {
	data, code, err := apiDelete(modelQueryPath("/v1/model/delete", name))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if code == 404 {
		fmt.Fprintf(os.Stderr, "model %q not found\n", name)
		os.Exit(1)
	}
	var result map[string]string
	json.Unmarshal(data, &result)
	fmt.Printf("Deleted: %s\n", name)
}

func cmdStatus() {
	data, code, err := apiGet("/health")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Registry unreachable: %v\n", err)
		os.Exit(1)
	}
	if code != 200 {
		fmt.Fprintf(os.Stderr, "Registry unhealthy: HTTP %d\n", code)
		os.Exit(1)
	}
	var result map[string]interface{}
	json.Unmarshal(data, &result)
	out, _ := json.MarshalIndent(result, "", "  ")
	fmt.Println(string(out))
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}

	switch os.Args[1] {
	case "list", "ls":
		cmdList()
	case "info":
		if len(os.Args) < 3 {
			usage()
		}
		cmdInfo(os.Args[2])
	case "verify":
		if len(os.Args) < 3 {
			usage()
		}
		cmdVerify(os.Args[2])
	case "path":
		if len(os.Args) < 3 {
			usage()
		}
		cmdPath(os.Args[2])
	case "delete", "rm":
		if len(os.Args) < 3 {
			usage()
		}
		cmdDelete(os.Args[2])
	case "status":
		cmdStatus()
	default:
		usage()
	}
}
