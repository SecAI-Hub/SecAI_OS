package main

import (
	"fmt"
	"time"
)

// LineageEntry records one step in a model's derivation chain.
type LineageEntry struct {
	Step        int       `json:"step" yaml:"step"`
	Action      string    `json:"action" yaml:"action"`           // download, quantize, fine-tune, merge, promote
	Description string    `json:"description" yaml:"description"`
	InputHash   string    `json:"input_hash,omitempty" yaml:"input_hash,omitempty"`
	OutputHash  string    `json:"output_hash,omitempty" yaml:"output_hash,omitempty"`
	Tool        string    `json:"tool,omitempty" yaml:"tool,omitempty"`
	Timestamp   string    `json:"timestamp" yaml:"timestamp"`
	Actor       string    `json:"actor,omitempty" yaml:"actor,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// LineageChain is the full derivation history for a model artifact.
type LineageChain struct {
	ArtifactName string         `json:"artifact_name" yaml:"artifact_name"`
	ArtifactHash string         `json:"artifact_hash" yaml:"artifact_hash"`
	Entries      []LineageEntry `json:"entries" yaml:"entries"`
}

// NewLineageChain starts a lineage chain for a model artifact.
func NewLineageChain(name, hash string) *LineageChain {
	return &LineageChain{
		ArtifactName: name,
		ArtifactHash: hash,
	}
}

// AddEntry appends a lineage step.
func (lc *LineageChain) AddEntry(action, description, inputHash, outputHash, tool, actor string, meta map[string]string) {
	lc.Entries = append(lc.Entries, LineageEntry{
		Step:        len(lc.Entries) + 1,
		Action:      action,
		Description: description,
		InputHash:   inputHash,
		OutputHash:  outputHash,
		Tool:        tool,
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
		Actor:       actor,
		Metadata:    meta,
	})
}

// BuildQuantizationLineage creates lineage entries for a quantized model.
func BuildQuantizationLineage(baseModel, baseHash, quantMethod, outputHash, quantizer string) *LineageChain {
	chain := NewLineageChain(baseModel+"."+quantMethod, outputHash)

	chain.AddEntry(
		"download",
		fmt.Sprintf("base model obtained: %s", baseModel),
		"", baseHash, "", "operator", nil,
	)

	chain.AddEntry(
		"quantize",
		fmt.Sprintf("quantized with method %s", quantMethod),
		baseHash, outputHash, "llama.cpp/quantize",
		quantizer,
		map[string]string{
			"method":     quantMethod,
			"base_model": baseModel,
		},
	)

	return chain
}

// BuildAdapterLineage creates lineage for a model with applied adapters.
func BuildAdapterLineage(baseModel, baseHash string, adapters []Adapter, finalHash string) *LineageChain {
	chain := NewLineageChain(baseModel+"+adapters", finalHash)

	chain.AddEntry(
		"download",
		fmt.Sprintf("base model: %s", baseModel),
		"", baseHash, "", "operator", nil,
	)

	prevHash := baseHash
	for _, adapter := range adapters {
		outHash := adapter.Hash
		if outHash == "" {
			outHash = finalHash
		}
		chain.AddEntry(
			"fine-tune",
			fmt.Sprintf("applied adapter: %s (type=%s)", adapter.Name, adapter.Type),
			prevHash, outHash, adapter.Type,
			"",
			map[string]string{
				"adapter_name": adapter.Name,
				"adapter_type": adapter.Type,
			},
		)
		prevHash = outHash
	}

	return chain
}

// BuildPromotionLineage adds a promotion step (quarantine → approved).
func (lc *LineageChain) AddPromotion(status, actor, reason string) {
	lc.AddEntry(
		"promote",
		fmt.Sprintf("promotion to %s: %s", status, reason),
		lc.ArtifactHash, lc.ArtifactHash, "ai-model-registry",
		actor,
		map[string]string{
			"promotion_status": status,
			"reason":           reason,
		},
	)
}

// ToProperties converts lineage into CycloneDX properties for embedding in a component.
func (lc *LineageChain) ToProperties() []Property {
	var props []Property
	for _, e := range lc.Entries {
		props = append(props, Property{
			Name:  fmt.Sprintf("secai:lineage:step%d:%s", e.Step, e.Action),
			Value: e.Description,
		})
	}
	return props
}

// Verify checks that the hash chain is internally consistent
// (each step's output_hash matches the next step's input_hash).
func (lc *LineageChain) Verify() (bool, int) {
	for i := 1; i < len(lc.Entries); i++ {
		prev := lc.Entries[i-1]
		curr := lc.Entries[i]
		if prev.OutputHash != "" && curr.InputHash != "" && prev.OutputHash != curr.InputHash {
			return false, i
		}
	}
	return true, -1
}
