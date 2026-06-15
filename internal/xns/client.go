package xns

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	blockTime        = 2 * time.Minute
	unfinalizedCache = time.Minute
	maxResponseSize  = 1 << 20
	requestTimeout   = 15 * time.Second
)

var ErrNotFound = errors.New("XNS name is not claimed")

type Result struct {
	Destination string
	CacheUntil  time.Time
}

type Client struct {
	indexer string
	network string
	http    *http.Client
}

type lookupResponse struct {
	Found           bool     `json:"found"`
	Name            string   `json:"name"`
	OwnerKey        string   `json:"owner_key"`
	RemainingBlocks uint64   `json:"remaining_blocks"`
	Finalized       bool     `json:"finalized"`
	SourceTxIDs     []string `json:"source_txids"`
}

func New(indexer, network string) (*Client, error) {
	indexer = strings.TrimRight(indexer, "/")
	parsed, err := url.Parse(indexer)
	if err != nil {
		return nil, err
	}
	if (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("indeXer must be an HTTP or HTTPS URL")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("indeXer URL must not contain a query or fragment")
	}
	if network != "tor" && network != "i2p" {
		return nil, errors.New("network must be tor or i2p")
	}
	return &Client{
		indexer: indexer,
		network: network,
		http:    &http.Client{Timeout: requestTimeout},
	}, nil
}

func (c *Client) Lookup(ctx context.Context, name string) (Result, error) {
	if err := ValidName(name); err != nil {
		return Result{}, err
	}
	endpoint := c.indexer + "/lookup?name=" + url.QueryEscape(name)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Result{}, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("indeXer lookup: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return Result{}, fmt.Errorf("read indeXer response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("indeXer returned HTTP %d", resp.StatusCode)
	}

	var out lookupResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return Result{}, errors.New("indeXer returned invalid JSON")
	}
	if !out.Found {
		return Result{}, ErrNotFound
	}
	if out.Name != name {
		return Result{}, errors.New("indeXer returned a different name")
	}
	if out.RemainingBlocks == 0 {
		return Result{}, ErrNotFound
	}
	destination, err := DestinationFromOwnerKey(out.OwnerKey, c.network)
	if err != nil {
		return Result{}, fmt.Errorf("invalid owner key from indeXer: %w", err)
	}
	if len(out.SourceTxIDs) == 0 {
		return Result{}, errors.New("indeXer returned no source transactions")
	}

	lifetime := durationForBlocks(out.RemainingBlocks)
	if !out.Finalized && lifetime > unfinalizedCache {
		lifetime = unfinalizedCache
	}
	return Result{Destination: destination, CacheUntil: time.Now().Add(lifetime)}, nil
}

func durationForBlocks(blocks uint64) time.Duration {
	maxBlocks := uint64((1<<63 - 1) / int64(blockTime))
	if blocks > maxBlocks {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(blocks) * blockTime
}
