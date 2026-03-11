package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// Document and chunk types
// ---------------------------------------------------------------------------

// Document represents an ingested source with sensitivity metadata.
type Document struct {
	ID               string            `json:"id"`
	Name             string            `json:"name"`
	Source           string            `json:"source"`              // vault, upload, crawl, manual
	SensitivityLabel string            `json:"sensitivity_label"`   // public, internal, confidential, restricted
	TrustLevel       string            `json:"trust_level"`         // verified, unverified, untrusted
	IngestedAt       string            `json:"ingested_at"`
	Labels           map[string]string `json:"labels,omitempty"`    // arbitrary key-value
	ContentHash      string            `json:"content_hash"`
	ChunkCount       int               `json:"chunk_count"`
}

// Chunk is a segment of a document, labeled and scanned.
type Chunk struct {
	ID               string            `json:"id"`
	DocumentID       string            `json:"document_id"`
	Index            int               `json:"index"`
	Content          string            `json:"content"`
	SensitivityLabel string            `json:"sensitivity_label"`
	TrustLevel       string            `json:"trust_level"`
	Labels           map[string]string `json:"labels,omitempty"`
	Scan             ScanResult        `json:"scan"`
	ContentHash      string            `json:"content_hash"`
}

// RetentionConfig controls document/chunk storage limits.
type RetentionConfig struct {
	MaxDocuments   int `yaml:"max_documents"`
	MaxTotalChunks int `yaml:"max_total_chunks"`
	TTLDays        int `yaml:"ttl_days"`
}

// ---------------------------------------------------------------------------
// ID generation
// ---------------------------------------------------------------------------

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%d-%s", time.Now().UnixMilli(), hex.EncodeToString(b))
}

func hashContent(content string) string {
	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:])
}

// ---------------------------------------------------------------------------
// Chunking
// ---------------------------------------------------------------------------

// chunkDocument splits content into chunks by paragraphs.
// Each chunk inherits the document's sensitivity label and trust level.
func chunkDocument(doc Document, content string) []Chunk {
	paragraphs := splitParagraphs(content)
	chunks := make([]Chunk, 0, len(paragraphs))

	for i, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			continue
		}

		chunk := Chunk{
			ID:               fmt.Sprintf("%s-c%d", doc.ID, i),
			DocumentID:       doc.ID,
			Index:            i,
			Content:          para,
			SensitivityLabel: doc.SensitivityLabel,
			TrustLevel:       doc.TrustLevel,
			Labels:           copyLabels(doc.Labels),
			ContentHash:      hashContent(para),
		}
		chunks = append(chunks, chunk)
	}
	return chunks
}

// splitParagraphs splits text by double newlines or significant breaks.
func splitParagraphs(content string) []string {
	// Normalize line endings.
	content = strings.ReplaceAll(content, "\r\n", "\n")

	// Split on double newlines.
	parts := strings.Split(content, "\n\n")

	// If only one chunk and it's long, split by single newlines with a size limit.
	if len(parts) == 1 && len(content) > 1000 {
		var result []string
		lines := strings.Split(content, "\n")
		var buf strings.Builder
		for _, line := range lines {
			if buf.Len()+len(line) > 800 && buf.Len() > 0 {
				result = append(result, buf.String())
				buf.Reset()
			}
			if buf.Len() > 0 {
				buf.WriteByte('\n')
			}
			buf.WriteString(line)
		}
		if buf.Len() > 0 {
			result = append(result, buf.String())
		}
		return result
	}

	return parts
}

func copyLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cp := make(map[string]string, len(labels))
	for k, v := range labels {
		cp[k] = v
	}
	return cp
}

// ---------------------------------------------------------------------------
// Document store (JSONL file-backed, in-memory indexed)
// ---------------------------------------------------------------------------

// DocumentStore manages documents and chunks with fsync durability.
type DocumentStore struct {
	mu        sync.RWMutex
	documents []Document
	chunks    []Chunk
	docIndex  map[string]int   // doc ID -> index in documents
	chunkByID map[string]int   // chunk ID -> index in chunks
	docChunks map[string][]int // doc ID -> chunk indices

	docFile   *os.File
	chunkFile *os.File
	dataDir   string
	retention RetentionConfig
}

// NewDocumentStore creates or opens a document store with retention controls.
func NewDocumentStore(dataDir string, retention RetentionConfig) (*DocumentStore, error) {
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}

	store := &DocumentStore{
		docIndex:  make(map[string]int),
		chunkByID: make(map[string]int),
		docChunks: make(map[string][]int),
		dataDir:   dataDir,
		retention: retention,
	}

	// Load existing documents (corruption-tolerant: skip bad lines).
	docPath := dataDir + "/documents.jsonl"
	if data, err := os.ReadFile(docPath); err == nil {
		for lineNum, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var d Document
			if err := json.Unmarshal([]byte(line), &d); err != nil {
				log.Printf("warning: skipping corrupt document at line %d: %v", lineNum+1, err)
				continue
			}
			idx := len(store.documents)
			store.documents = append(store.documents, d)
			store.docIndex[d.ID] = idx
		}
	}

	// Load existing chunks (corruption-tolerant: skip bad lines).
	chunkPath := dataDir + "/chunks.jsonl"
	if data, err := os.ReadFile(chunkPath); err == nil {
		for lineNum, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var c Chunk
			if err := json.Unmarshal([]byte(line), &c); err != nil {
				log.Printf("warning: skipping corrupt chunk at line %d: %v", lineNum+1, err)
				continue
			}
			idx := len(store.chunks)
			store.chunks = append(store.chunks, c)
			store.chunkByID[c.ID] = idx
			store.docChunks[c.DocumentID] = append(store.docChunks[c.DocumentID], idx)
		}
	}

	// Open files for appending.
	df, err := os.OpenFile(docPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return nil, fmt.Errorf("open documents file: %w", err)
	}
	store.docFile = df

	cf, err := os.OpenFile(chunkPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		df.Close()
		return nil, fmt.Errorf("open chunks file: %w", err)
	}
	store.chunkFile = cf

	return store, nil
}

// IngestRequest is the input for document ingestion.
type IngestRequest struct {
	Name             string            `json:"name"`
	Content          string            `json:"content"`
	Source           string            `json:"source"`
	SensitivityLabel string            `json:"sensitivity_label"`
	TrustLevel       string            `json:"trust_level"`
	Labels           map[string]string `json:"labels,omitempty"`
}

// Ingest adds a document and its chunks to the store.
// Enforces retention limits (max_documents, max_total_chunks).
func (s *DocumentStore) Ingest(req IngestRequest, scanCfg ScannerConfig) (Document, []Chunk, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Enforce retention: max documents.
	if s.retention.MaxDocuments > 0 && len(s.documents) >= s.retention.MaxDocuments {
		return Document{}, nil, fmt.Errorf("max documents reached (%d)", s.retention.MaxDocuments)
	}

	if req.SensitivityLabel == "" {
		req.SensitivityLabel = "internal"
	}
	if req.TrustLevel == "" {
		req.TrustLevel = "unverified"
	}
	if req.Source == "" {
		req.Source = "upload"
	}

	doc := Document{
		ID:               generateID(),
		Name:             req.Name,
		Source:           req.Source,
		SensitivityLabel: req.SensitivityLabel,
		TrustLevel:       req.TrustLevel,
		IngestedAt:       time.Now().UTC().Format(time.RFC3339),
		Labels:           req.Labels,
		ContentHash:      hashContent(req.Content),
	}

	// Chunk the content.
	chunks := chunkDocument(doc, req.Content)

	// Enforce retention: max total chunks.
	if s.retention.MaxTotalChunks > 0 && len(s.chunks)+len(chunks) > s.retention.MaxTotalChunks {
		return Document{}, nil, fmt.Errorf("max total chunks would be exceeded (%d + %d > %d)", len(s.chunks), len(chunks), s.retention.MaxTotalChunks)
	}

	// Scan each chunk.
	for i := range chunks {
		chunks[i].Scan = ScanContent(chunks[i].Content, scanCfg)
	}

	doc.ChunkCount = len(chunks)

	// Persist document with fsync.
	docData, _ := json.Marshal(doc)
	if _, err := s.docFile.Write(append(docData, '\n')); err != nil {
		return Document{}, nil, fmt.Errorf("write document: %w", err)
	}
	if err := s.docFile.Sync(); err != nil {
		return Document{}, nil, fmt.Errorf("sync document file: %w", err)
	}

	docIdx := len(s.documents)
	s.documents = append(s.documents, doc)
	s.docIndex[doc.ID] = docIdx

	// Persist chunks with fsync.
	for _, c := range chunks {
		chunkData, _ := json.Marshal(c)
		if _, err := s.chunkFile.Write(append(chunkData, '\n')); err != nil {
			return doc, nil, fmt.Errorf("write chunk: %w", err)
		}

		cIdx := len(s.chunks)
		s.chunks = append(s.chunks, c)
		s.chunkByID[c.ID] = cIdx
		s.docChunks[doc.ID] = append(s.docChunks[doc.ID], cIdx)
	}
	if err := s.chunkFile.Sync(); err != nil {
		return doc, chunks, fmt.Errorf("sync chunk file: %w", err)
	}

	return doc, chunks, nil
}

// GetDocument returns a document by ID.
func (s *DocumentStore) GetDocument(id string) (Document, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.docIndex[id]
	if !ok {
		return Document{}, false
	}
	return s.documents[idx], true
}

// GetChunk returns a chunk by ID.
func (s *DocumentStore) GetChunk(id string) (Chunk, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx, ok := s.chunkByID[id]
	if !ok {
		return Chunk{}, false
	}
	return s.chunks[idx], true
}

// ChunkFilter specifies query criteria for chunks.
type ChunkFilter struct {
	DocumentID       string
	SensitivityLabel string
	TrustLevel       string
	Limit            int
}

// QueryChunks returns chunks matching the filter.
func (s *DocumentStore) QueryChunks(filter ChunkFilter) []Chunk {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var candidates []Chunk
	if filter.DocumentID != "" {
		indices, ok := s.docChunks[filter.DocumentID]
		if !ok {
			return nil
		}
		for _, idx := range indices {
			candidates = append(candidates, s.chunks[idx])
		}
	} else {
		candidates = s.chunks
	}

	var results []Chunk
	for _, c := range candidates {
		if filter.SensitivityLabel != "" && c.SensitivityLabel != filter.SensitivityLabel {
			continue
		}
		if filter.TrustLevel != "" && c.TrustLevel != filter.TrustLevel {
			continue
		}
		results = append(results, c)
		if filter.Limit > 0 && len(results) >= filter.Limit {
			break
		}
	}
	return results
}

// ListDocuments returns all documents, newest first.
func (s *DocumentStore) ListDocuments() []Document {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]Document, len(s.documents))
	copy(result, s.documents)
	sort.Slice(result, func(i, j int) bool {
		return result[i].IngestedAt > result[j].IngestedAt
	})
	return result
}

// AllChunks returns every chunk (for policy evaluation).
func (s *DocumentStore) AllChunks() []Chunk {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Chunk, len(s.chunks))
	copy(result, s.chunks)
	return result
}

// DocumentCount returns total documents.
func (s *DocumentStore) DocumentCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.documents)
}

// ChunkCount returns total chunks.
func (s *DocumentStore) ChunkCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.chunks)
}

// ---------------------------------------------------------------------------
// Deletion and retention
// ---------------------------------------------------------------------------

// DeleteDocument removes a document and its chunks, rewriting JSONL files.
func (s *DocumentStore) DeleteDocument(docID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.docIndex[docID]; !ok {
		return fmt.Errorf("document not found: %s", docID)
	}

	// Rebuild arrays excluding the deleted document and its chunks.
	deletedChunks := make(map[int]bool)
	for _, idx := range s.docChunks[docID] {
		deletedChunks[idx] = true
	}

	var newDocs []Document
	newDocIndex := make(map[string]int)
	for _, d := range s.documents {
		if d.ID == docID {
			continue
		}
		idx := len(newDocs)
		newDocs = append(newDocs, d)
		newDocIndex[d.ID] = idx
	}

	var newChunks []Chunk
	newChunkByID := make(map[string]int)
	newDocChunks := make(map[string][]int)
	for i, c := range s.chunks {
		if deletedChunks[i] {
			continue
		}
		idx := len(newChunks)
		newChunks = append(newChunks, c)
		newChunkByID[c.ID] = idx
		newDocChunks[c.DocumentID] = append(newDocChunks[c.DocumentID], idx)
	}

	s.documents = newDocs
	s.docIndex = newDocIndex
	s.chunks = newChunks
	s.chunkByID = newChunkByID
	s.docChunks = newDocChunks

	// Rewrite JSONL files.
	if err := s.rewriteDocFile(); err != nil {
		return fmt.Errorf("rewrite documents: %w", err)
	}
	if err := s.rewriteChunkFile(); err != nil {
		return fmt.Errorf("rewrite chunks: %w", err)
	}
	return nil
}

// PurgeExpired removes documents older than the retention TTL.
// Returns the number of documents purged.
func (s *DocumentStore) PurgeExpired() (int, error) {
	if s.retention.TTLDays <= 0 {
		return 0, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().UTC().AddDate(0, 0, -s.retention.TTLDays).Format(time.RFC3339)
	var expiredIDs []string
	for _, d := range s.documents {
		if d.IngestedAt < cutoff {
			expiredIDs = append(expiredIDs, d.ID)
		}
	}

	if len(expiredIDs) == 0 {
		return 0, nil
	}

	// Build set of deleted doc IDs and chunk indices.
	deletedDocs := make(map[string]bool)
	deletedChunks := make(map[int]bool)
	for _, id := range expiredIDs {
		deletedDocs[id] = true
		for _, idx := range s.docChunks[id] {
			deletedChunks[idx] = true
		}
	}

	// Rebuild arrays.
	var newDocs []Document
	newDocIndex := make(map[string]int)
	for _, d := range s.documents {
		if deletedDocs[d.ID] {
			continue
		}
		idx := len(newDocs)
		newDocs = append(newDocs, d)
		newDocIndex[d.ID] = idx
	}

	var newChunks []Chunk
	newChunkByID := make(map[string]int)
	newDocChunks := make(map[string][]int)
	for i, c := range s.chunks {
		if deletedChunks[i] {
			continue
		}
		idx := len(newChunks)
		newChunks = append(newChunks, c)
		newChunkByID[c.ID] = idx
		newDocChunks[c.DocumentID] = append(newDocChunks[c.DocumentID], idx)
	}

	s.documents = newDocs
	s.docIndex = newDocIndex
	s.chunks = newChunks
	s.chunkByID = newChunkByID
	s.docChunks = newDocChunks

	// Rewrite JSONL files.
	if err := s.rewriteDocFile(); err != nil {
		return 0, fmt.Errorf("rewrite documents: %w", err)
	}
	if err := s.rewriteChunkFile(); err != nil {
		return 0, fmt.Errorf("rewrite chunks: %w", err)
	}

	return len(expiredIDs), nil
}

// rewriteDocFile rewrites the documents JSONL from in-memory state.
func (s *DocumentStore) rewriteDocFile() error {
	if s.docFile != nil {
		s.docFile.Close()
	}

	path := s.dataDir + "/documents.jsonl"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	for _, d := range s.documents {
		data, _ := json.Marshal(d)
		f.Write(append(data, '\n'))
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Reopen for appending.
	f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	s.docFile = f
	return nil
}

// rewriteChunkFile rewrites the chunks JSONL from in-memory state.
func (s *DocumentStore) rewriteChunkFile() error {
	if s.chunkFile != nil {
		s.chunkFile.Close()
	}

	path := s.dataDir + "/chunks.jsonl"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0640)
	if err != nil {
		return err
	}
	for _, c := range s.chunks {
		data, _ := json.Marshal(c)
		f.Write(append(data, '\n'))
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	f.Close()

	// Reopen for appending.
	f, err = os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	s.chunkFile = f
	return nil
}

// Close closes the store files.
func (s *DocumentStore) Close() error {
	if s.docFile != nil {
		s.docFile.Close()
	}
	if s.chunkFile != nil {
		s.chunkFile.Close()
	}
	return nil
}
