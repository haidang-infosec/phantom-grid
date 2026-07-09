package exporter

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"phantom-grid/internal/config"
)

// ELKExporter sends logs to Elasticsearch
type ELKExporter struct {
	config      config.ELKConfiguration
	client      ElasticsearchClient
	buffer      []map[string]interface{}
	bufferMutex sync.Mutex
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup
}

// ElasticsearchClient interface for Elasticsearch operations
type ElasticsearchClient interface {
	BulkIndex(index string, documents []map[string]interface{}) error
	Close() error
}

// NewELKExporter creates a new ELK exporter
func NewELKExporter(cfg config.ELKConfiguration) (*ELKExporter, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("ELK exporter is disabled")
	}

	client, err := NewElasticsearchClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Elasticsearch client: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	exporter := &ELKExporter{
		config: cfg,
		client: client,
		buffer: make([]map[string]interface{}, 0, cfg.BatchSize),
		ctx:    ctx,
		cancel: cancel,
	}

	// Start background flush goroutine
	exporter.wg.Add(1)
	go exporter.flushLoop()

	return exporter, nil
}

// Export sends a log entry to Elasticsearch (buffered)
func (e *ELKExporter) Export(event map[string]interface{}) error {
	if !e.config.Enabled {
		return nil
	}

	e.bufferMutex.Lock()
	defer e.bufferMutex.Unlock()

	// Add timestamp if not present
	if _, ok := event["@timestamp"]; !ok {
		event["@timestamp"] = time.Now().UTC().Format(time.RFC3339)
	}

	e.buffer = append(e.buffer, event)

	// Flush if buffer is full
	if len(e.buffer) >= e.config.BatchSize {
		return e.flushLocked()
	}

	return nil
}

// flushLocked flushes the buffer (must be called with bufferMutex locked)
func (e *ELKExporter) flushLocked() error {
	if len(e.buffer) == 0 {
		return nil
	}

	// Copy buffer and clear
	toSend := make([]map[string]interface{}, len(e.buffer))
	copy(toSend, e.buffer)
	e.buffer = e.buffer[:0]

	// Unlock before network call
	e.bufferMutex.Unlock()

	// Send to Elasticsearch
	err := e.client.BulkIndex(e.config.Index, toSend)

	// Re-lock
	e.bufferMutex.Lock()

	if err != nil {
		log.Printf("[ELK] Failed to send batch: %v", err)
		// Re-add failed documents to buffer (simple retry)
		e.buffer = append(toSend, e.buffer...)
		return err
	}

	return nil
}

// Flush flushes the buffer immediately
func (e *ELKExporter) Flush() error {
	e.bufferMutex.Lock()
	defer e.bufferMutex.Unlock()
	return e.flushLocked()
}

// flushLoop periodically flushes the buffer
func (e *ELKExporter) flushLoop() {
	defer e.wg.Done()

	ticker := time.NewTicker(time.Duration(e.config.FlushInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.ctx.Done():
			// Final flush on shutdown
			_ = e.Flush()
			return
		case <-ticker.C:
			_ = e.Flush()
		}
	}
}

// Close closes the exporter and flushes remaining data
func (e *ELKExporter) Close() error {
	e.cancel()
	e.wg.Wait()

	// Final flush
	if err := e.Flush(); err != nil {
		log.Printf("[ELK] Error during final flush: %v", err)
	}

	if e.client != nil {
		return e.client.Close()
	}

	return nil
}

// ElasticsearchHTTPClient implements ElasticsearchClient using HTTP
type ElasticsearchHTTPClient struct {
	addresses  []string
	username   string
	password   string
	httpClient *http.Client
}

// NewElasticsearchClient creates a new Elasticsearch HTTP client
func NewElasticsearchClient(cfg config.ELKConfiguration) (ElasticsearchClient, error) {
	// For now, use simple HTTP client
	// In production, consider using official Elasticsearch Go client
	return NewElasticsearchHTTPClient(cfg)
}

// NewElasticsearchHTTPClient creates HTTP-based Elasticsearch client
func NewElasticsearchHTTPClient(cfg config.ELKConfiguration) (*ElasticsearchHTTPClient, error) {
	client := &ElasticsearchHTTPClient{
		addresses: cfg.Addresses,
		username:  cfg.Username,
		password:  cfg.Password,
	}

	// Configure HTTP client
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: cfg.SkipVerify,
		},
	}

	if cfg.UseTLS {
		// Enable TLS
	}

	client.httpClient = &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	return client, nil
}

// BulkIndex sends bulk index requests to Elasticsearch
func (c *ElasticsearchHTTPClient) BulkIndex(index string, documents []map[string]interface{}) error {
	if len(documents) == 0 {
		return nil
	}

	// Build bulk request body
	var buf bytes.Buffer
	for _, doc := range documents {
		// Action line
		action := map[string]interface{}{
			"index": map[string]interface{}{
				"_index": index,
			},
		}
		actionJSON, _ := json.Marshal(action)
		buf.Write(actionJSON)
		buf.WriteString("\n")

		// Document line
		docJSON, _ := json.Marshal(doc)
		buf.Write(docJSON)
		buf.WriteString("\n")
	}

	// Try each address until one succeeds
	var lastErr error
	for _, addr := range c.addresses {
		url := fmt.Sprintf("%s/_bulk", addr)
		req, err := http.NewRequest("POST", url, &buf)
		if err != nil {
			lastErr = err
			continue
		}

		req.Header.Set("Content-Type", "application/json")
		if c.username != "" && c.password != "" {
			req.SetBasicAuth(c.username, c.password)
		}

		resp, err := c.httpClient.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		// Read error response
		var errResp map[string]interface{}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		lastErr = fmt.Errorf("Elasticsearch error: %v (status: %d)", errResp, resp.StatusCode)
	}

	return fmt.Errorf("failed to send to all Elasticsearch addresses: %w", lastErr)
}

// Close closes the HTTP client
func (c *ElasticsearchHTTPClient) Close() error {
	// HTTP client doesn't need explicit close
	return nil
}

