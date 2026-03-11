package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ---------- CycloneDX-aligned BOM types ----------

// ModelBOM is the top-level CycloneDX ML-BOM document.
type ModelBOM struct {
	BOMFormat      string         `json:"bomFormat" yaml:"bomFormat"`
	SpecVersion    string         `json:"specVersion" yaml:"specVersion"`
	Version        int            `json:"version" yaml:"version"`
	SerialNumber   string         `json:"serialNumber" yaml:"serialNumber"`
	Metadata       BOMMetadata    `json:"metadata" yaml:"metadata"`
	Components     []Component    `json:"components" yaml:"components"`
	Dependencies   []Dependency   `json:"dependencies,omitempty" yaml:"dependencies,omitempty"`
}

// Dependency records a CycloneDX dependency relationship.
type Dependency struct {
	Ref       string   `json:"ref" yaml:"ref"`
	DependsOn []string `json:"dependsOn,omitempty" yaml:"dependsOn,omitempty"`
}

// BOMMetadata describes when and how the BOM was generated.
type BOMMetadata struct {
	Timestamp string      `json:"timestamp" yaml:"timestamp"`
	Tools     []BOMTool   `json:"tools" yaml:"tools"`
	Component *Component  `json:"component,omitempty" yaml:"component,omitempty"`
}

// BOMTool identifies the tool that generated the BOM.
type BOMTool struct {
	Vendor  string `json:"vendor" yaml:"vendor"`
	Name    string `json:"name" yaml:"name"`
	Version string `json:"version" yaml:"version"`
}

// Component is a CycloneDX component (model, tokenizer, adapter, etc.).
type Component struct {
	Type            string         `json:"type" yaml:"type"`
	BOMRef          string         `json:"bom-ref,omitempty" yaml:"bom-ref,omitempty"`
	Name            string         `json:"name" yaml:"name"`
	Version         string         `json:"version,omitempty" yaml:"version,omitempty"`
	Description     string         `json:"description,omitempty" yaml:"description,omitempty"`
	Hashes          []Hash         `json:"hashes,omitempty" yaml:"hashes,omitempty"`
	Licenses        []License      `json:"licenses,omitempty" yaml:"licenses,omitempty"`
	ExternalRefs    []ExternalRef  `json:"externalReferences,omitempty" yaml:"externalReferences,omitempty"`
	Properties      []Property     `json:"properties,omitempty" yaml:"properties,omitempty"`
	ModelCard       *ModelCard     `json:"modelCard,omitempty" yaml:"modelCard,omitempty"`
	Evidence        []EvidenceItem `json:"evidence,omitempty" yaml:"evidence,omitempty"`
}

// Hash is a content hash (CycloneDX format).
type Hash struct {
	Algorithm string `json:"alg" yaml:"alg"`
	Content   string `json:"content" yaml:"content"`
}

// License for the model.
type License struct {
	ID   string `json:"id,omitempty" yaml:"id,omitempty"`
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	URL  string `json:"url,omitempty" yaml:"url,omitempty"`
}

// ExternalRef links to external resources.
type ExternalRef struct {
	Type string `json:"type" yaml:"type"`
	URL  string `json:"url" yaml:"url"`
}

// Property is a key-value extension point (SecAI trust metadata lives here).
type Property struct {
	Name  string `json:"name" yaml:"name"`
	Value string `json:"value" yaml:"value"`
}

// ModelCard captures ML-specific metadata.
type ModelCard struct {
	BaseModel       string        `json:"base_model,omitempty" yaml:"base_model,omitempty"`
	ModelFamily     string        `json:"model_family,omitempty" yaml:"model_family,omitempty"`
	Parameters      string        `json:"parameters,omitempty" yaml:"parameters,omitempty"`
	Quantization    *Quantization `json:"quantization,omitempty" yaml:"quantization,omitempty"`
	Tokenizer       *Tokenizer    `json:"tokenizer,omitempty" yaml:"tokenizer,omitempty"`
	Adapters        []Adapter     `json:"adapters,omitempty" yaml:"adapters,omitempty"`
	TrustLabels     []string      `json:"trust_labels,omitempty" yaml:"trust_labels,omitempty"`
	PromotionStatus string        `json:"promotion_status,omitempty" yaml:"promotion_status,omitempty"`
}

// Quantization records quantization lineage.
type Quantization struct {
	Method     string `json:"method" yaml:"method"`         // Q4_K_M, Q5_K_S, etc.
	BitsPerWeight float64 `json:"bits_per_weight,omitempty" yaml:"bits_per_weight,omitempty"`
	BaseModelHash string `json:"base_model_hash,omitempty" yaml:"base_model_hash,omitempty"`
	QuantizedBy   string `json:"quantized_by,omitempty" yaml:"quantized_by,omitempty"`
	QuantizedAt   string `json:"quantized_at,omitempty" yaml:"quantized_at,omitempty"`
}

// Tokenizer describes the tokenizer associated with a model.
type Tokenizer struct {
	Name    string `json:"name,omitempty" yaml:"name,omitempty"`
	Type    string `json:"type,omitempty" yaml:"type,omitempty"` // BPE, SentencePiece, etc.
	Hash    string `json:"hash,omitempty" yaml:"hash,omitempty"`
	Source  string `json:"source,omitempty" yaml:"source,omitempty"`
}

// Adapter represents a LoRA or other fine-tuning adapter.
type Adapter struct {
	Name       string `json:"name" yaml:"name"`
	Type       string `json:"type" yaml:"type"` // lora, qlora, etc.
	Rank       int    `json:"rank,omitempty" yaml:"rank,omitempty"`
	Hash       string `json:"hash,omitempty" yaml:"hash,omitempty"`
	BaseModel  string `json:"base_model,omitempty" yaml:"base_model,omitempty"`
}

// ---------- BOM generation ----------

const bomToolVersion = "0.2.0"

// MaxFileSize is the maximum model file size to hash (10 GiB).
const MaxFileSize = 10 << 30

// GenerateBOM creates a BOM from a model directory or single file.
func GenerateBOM(path string, meta *ModelMetadata) (*ModelBOM, error) {
	info, err := os.Lstat(path) // Lstat to detect symlinks
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}

	// Reject symlinks, devices, FIFOs at the top level
	if !info.Mode().IsDir() && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to scan non-regular file: %s (mode=%s)", path, info.Mode())
	}

	bom := &ModelBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		Version:      1,
		SerialNumber: "urn:uuid:" + uuid.New().String(),
		Metadata: BOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []BOMTool{{
				Vendor:  "SecAI-Hub",
				Name:    "ai-model-bom",
				Version: bomToolVersion,
			}},
		},
	}

	if info.IsDir() {
		components, err := scanDirectory(path, meta)
		if err != nil {
			return nil, err
		}
		bom.Components = components
	} else {
		comp, err := scanFile(path, meta)
		if err != nil {
			return nil, err
		}
		bom.Components = []Component{comp}
	}

	// Wire lineage into generation when metadata has quantization/adapter info
	if meta != nil {
		wireLineage(bom, meta)
	}

	// Build dependency graph for multi-component BOMs
	bom.Dependencies = buildDependencies(bom.Components)

	// Set primary component
	if len(bom.Components) > 0 {
		primary := bom.Components[0]
		bom.Metadata.Component = &primary
	}

	return bom, nil
}

// wireLineage automatically embeds lineage properties when metadata provides lineage info.
func wireLineage(bom *ModelBOM, meta *ModelMetadata) {
	for i, comp := range bom.Components {
		if comp.Type != "machine-learning-model" {
			continue
		}

		card := comp.ModelCard
		if card == nil {
			continue
		}

		outputHash := ""
		if len(comp.Hashes) > 0 {
			outputHash = comp.Hashes[0].Content
		}

		var chain *LineageChain

		// Build quantization lineage
		if card.Quantization != nil && card.Quantization.Method != "" && meta.BaseModel != "" {
			baseHash := meta.BaseModelHash
			chain = BuildQuantizationLineage(
				meta.BaseModel, baseHash,
				card.Quantization.Method, outputHash,
				meta.QuantizedBy,
			)
		}

		// Build adapter lineage
		if len(card.Adapters) > 0 && meta.BaseModel != "" {
			baseHash := meta.BaseModelHash
			chain = BuildAdapterLineage(meta.BaseModel, baseHash, card.Adapters, outputHash)
		}

		// Add promotion step
		if chain != nil && meta.PromotionStatus != "" {
			chain.AddPromotion(meta.PromotionStatus, "", meta.PromotionReason)
		}

		// If no chain built but we have a base model, create a simple one
		if chain == nil && meta.BaseModel != "" {
			chain = NewLineageChain(comp.Name, outputHash)
			chain.AddEntry("download", fmt.Sprintf("base model: %s", meta.BaseModel),
				"", meta.BaseModelHash, "", "", nil)
			if meta.PromotionStatus != "" {
				chain.AddPromotion(meta.PromotionStatus, "", meta.PromotionReason)
			}
		}

		// Embed lineage as properties
		if chain != nil {
			bom.Components[i].Properties = append(bom.Components[i].Properties, chain.ToProperties()...)
		}
	}
}

// buildDependencies creates CycloneDX dependency relationships.
func buildDependencies(components []Component) []Dependency {
	if len(components) < 2 {
		return nil
	}

	var deps []Dependency
	var modelRef string

	for _, comp := range components {
		if comp.Type == "machine-learning-model" && modelRef == "" {
			modelRef = comp.BOMRef
		}
	}

	if modelRef == "" {
		return nil
	}

	// Tokenizers and adapters depend on the primary model
	var dependsOn []string
	for _, comp := range components {
		if comp.BOMRef == modelRef {
			continue
		}
		for _, prop := range comp.Properties {
			if prop.Name == "secai:component_type" && (prop.Value == "tokenizer" || prop.Value == "adapter") {
				dependsOn = append(dependsOn, comp.BOMRef)
			}
		}
	}

	if len(dependsOn) > 0 {
		deps = append(deps, Dependency{Ref: modelRef, DependsOn: dependsOn})
	}

	return deps
}

// scanDirectory walks a directory and creates components for model files.
// Rejects symlinks, devices, FIFOs, and files exceeding MaxFileSize.
func scanDirectory(dir string, meta *ModelMetadata) ([]Component, error) {
	var components []Component

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		// Reject non-regular files (symlinks, devices, FIFOs, sockets)
		if !info.Mode().IsRegular() {
			return nil
		}

		// Enforce max file size
		if info.Size() > MaxFileSize {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(info.Name()))
		switch ext {
		case ".gguf", ".bin", ".safetensors", ".pt", ".onnx":
			comp, err := scanFile(path, meta)
			if err != nil {
				return nil
			}
			components = append(components, comp)
		case ".json":
			if isTokenizerFile(info.Name()) {
				comp := buildTokenizerComponent(path, info)
				components = append(components, comp)
			}
		}
		return nil
	})

	return components, err
}

// scanFile creates a component from a single model file.
func scanFile(path string, meta *ModelMetadata) (Component, error) {
	info, err := os.Stat(path)
	if err != nil {
		return Component{}, err
	}

	hash, err := hashFileSHA256(path)
	if err != nil {
		return Component{}, err
	}

	name := info.Name()
	comp := Component{
		Type:   "machine-learning-model",
		BOMRef: name,
		Name:   name,
		Hashes: []Hash{{Algorithm: "SHA-256", Content: hash}},
		Properties: []Property{
			{Name: "secai:file_size", Value: fmt.Sprintf("%d", info.Size())},
			{Name: "secai:file_format", Value: detectFormat(name)},
		},
	}

	// Extract metadata from filename
	parsed := parseModelFilename(name)
	if parsed.ModelFamily != "" || parsed.Quantization != "" {
		card := &ModelCard{
			ModelFamily: parsed.ModelFamily,
			Parameters:  parsed.Parameters,
		}
		if parsed.Quantization != "" {
			card.Quantization = &Quantization{
				Method: parsed.Quantization,
			}
		}
		comp.ModelCard = card
	}

	// Apply user-supplied metadata
	if meta != nil {
		applyMetadata(&comp, meta)
	}

	return comp, nil
}

// buildTokenizerComponent creates a component for a tokenizer file.
func buildTokenizerComponent(path string, info os.FileInfo) Component {
	hash, _ := hashFileSHA256(path)
	return Component{
		Type:   "data",
		BOMRef: "tokenizer:" + info.Name(),
		Name:   info.Name(),
		Hashes: []Hash{{Algorithm: "SHA-256", Content: hash}},
		Properties: []Property{
			{Name: "secai:component_type", Value: "tokenizer"},
		},
	}
}

// ---------- metadata types ----------

// ModelMetadata is optional user-supplied metadata for BOM enrichment.
type ModelMetadata struct {
	Name            string   `yaml:"name,omitempty"`
	Version         string   `yaml:"version,omitempty"`
	Description     string   `yaml:"description,omitempty"`
	BaseModel       string   `yaml:"base_model,omitempty"`
	BaseModelHash   string   `yaml:"base_model_hash,omitempty"`
	ModelFamily     string   `yaml:"model_family,omitempty"`
	License         string   `yaml:"license,omitempty"`
	SourceURL       string   `yaml:"source_url,omitempty"`
	TrustLabels     []string `yaml:"trust_labels,omitempty"`
	PromotionStatus string   `yaml:"promotion_status,omitempty"`
	PromotionReason string   `yaml:"promotion_reason,omitempty"`
	QuantizedBy     string   `yaml:"quantized_by,omitempty"`
	QuantizedAt     string   `yaml:"quantized_at,omitempty"`
}

// applyMetadata enriches a component with user-supplied metadata.
func applyMetadata(comp *Component, meta *ModelMetadata) {
	if meta.Name != "" {
		comp.Name = meta.Name
	}
	if meta.Version != "" {
		comp.Version = meta.Version
	}
	if meta.Description != "" {
		comp.Description = meta.Description
	}
	if meta.License != "" {
		comp.Licenses = []License{{Name: meta.License}}
	}
	if meta.SourceURL != "" {
		comp.ExternalRefs = append(comp.ExternalRefs, ExternalRef{
			Type: "distribution",
			URL:  meta.SourceURL,
		})
	}

	if comp.ModelCard == nil {
		comp.ModelCard = &ModelCard{}
	}
	if meta.BaseModel != "" {
		comp.ModelCard.BaseModel = meta.BaseModel
	}
	if meta.ModelFamily != "" {
		comp.ModelCard.ModelFamily = meta.ModelFamily
	}
	if meta.TrustLabels != nil {
		comp.ModelCard.TrustLabels = meta.TrustLabels
	}
	if meta.PromotionStatus != "" {
		comp.ModelCard.PromotionStatus = meta.PromotionStatus
	}
	if meta.QuantizedBy != "" && comp.ModelCard.Quantization != nil {
		comp.ModelCard.Quantization.QuantizedBy = meta.QuantizedBy
	}
	if meta.QuantizedAt != "" && comp.ModelCard.Quantization != nil {
		comp.ModelCard.Quantization.QuantizedAt = meta.QuantizedAt
	}
}

// ---------- filename parsing ----------

// parsedFilename holds metadata extracted from a model filename.
type parsedFilename struct {
	ModelFamily  string
	Parameters   string
	Quantization string
	Format       string
}

var (
	// Match patterns like "mistral-7b-instruct-v0.3.Q4_K_M.gguf"
	reQuant  = regexp.MustCompile(`\.(Q\d[_\w]*|F16|F32|BF16)\.`)
	reParams = regexp.MustCompile(`(?i)(\d+\.?\d*[bBmM])`)
)

// parseModelFilename extracts metadata from a model filename.
func parseModelFilename(name string) parsedFilename {
	p := parsedFilename{Format: detectFormat(name)}

	// Extract quantization
	if m := reQuant.FindStringSubmatch(name); len(m) > 1 {
		p.Quantization = m[1]
	}

	// Extract parameter count
	if m := reParams.FindStringSubmatch(name); len(m) > 1 {
		p.Parameters = strings.ToUpper(m[1])
	}

	// Extract model family (everything before parameter count or quantization)
	base := strings.TrimSuffix(name, filepath.Ext(name))
	// Remove quantization suffix
	if p.Quantization != "" {
		base = strings.Replace(base, "."+p.Quantization, "", 1)
		base = strings.Replace(base, "-"+p.Quantization, "", 1)
	}
	// Clean up
	base = strings.TrimRight(base, ".-_ ")
	if base != "" {
		p.ModelFamily = base
	}

	return p
}

// detectFormat returns the model file format.
func detectFormat(name string) string {
	switch strings.ToLower(filepath.Ext(name)) {
	case ".gguf":
		return "GGUF"
	case ".safetensors":
		return "SafeTensors"
	case ".bin":
		return "PyTorch"
	case ".pt":
		return "PyTorch"
	case ".onnx":
		return "ONNX"
	default:
		return "unknown"
	}
}

func isTokenizerFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "tokenizer") || strings.Contains(lower, "vocab")
}

// ---------- helpers ----------

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
