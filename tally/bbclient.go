package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/valy0/otvoren-vot/tally/ceremony"
)

const (
	// defaultPageLimit is the number of ballots requested per page.
	defaultPageLimit = 1000

	// maxResponseBytes caps the size of a single HTTP response body
	// to prevent unbounded memory consumption from a misbehaving server.
	maxResponseBytes = 64 * 1024 * 1024 // 64 MiB
)

// BBClient fetches ballots and board status from the Bulletin Board service.
type BBClient struct {
	baseURL    string
	httpClient *http.Client
	pageLimit  int
}

// NewBBClient creates a BBClient pointing at the given Bulletin Board base URL.
func NewBBClient(baseURL string) *BBClient {
	return &BBClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		pageLimit: defaultPageLimit,
	}
}

// boardRootResponse is the JSON envelope returned by GET /api/v1/board/root.
type boardRootResponse struct {
	Data struct {
		RootSHA256 string `json:"root_sha256"`
		Sealed     bool   `json:"sealed"`
		Count      int    `json:"count"`
	} `json:"data"`
}

// IsSealed reports whether the bulletin board has been sealed (no more ballots
// will be accepted). This must be true before tallying can begin.
func (c *BBClient) IsSealed(ctx context.Context) (bool, error) {
	reqURL := c.baseURL + "/api/v1/board/root"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("bbclient: build root request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("bbclient: root request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("bbclient: root request returned %s", resp.Status)
	}

	var root boardRootResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&root); err != nil {
		return false, fmt.Errorf("bbclient: decode root response: %w", err)
	}

	return root.Data.Sealed, nil
}

// ballotPageResponse is the JSON envelope returned by GET /api/v1/board.
type ballotPageResponse struct {
	Data []ceremony.SerializedBallot `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
		Total  int    `json:"total"`
	} `json:"meta"`
}

// FetchAllBallots retrieves every ballot from the bulletin board using
// cursor-based pagination. It returns all ballots in submission order.
func (c *BBClient) FetchAllBallots(ctx context.Context) ([]ceremony.SerializedBallot, error) {
	var allBallots []ceremony.SerializedBallot
	cursor := ""

	for {
		page, nextCursor, err := c.fetchPage(ctx, cursor)
		if err != nil {
			return nil, err
		}

		allBallots = append(allBallots, page...)

		if nextCursor == "" {
			break
		}
		cursor = nextCursor
	}

	return allBallots, nil
}

// fetchPage retrieves a single page of ballots. It returns the ballots,
// the next cursor (empty string if this was the last page), and any error.
func (c *BBClient) fetchPage(ctx context.Context, cursor string) ([]ceremony.SerializedBallot, string, error) {
	reqURL, err := c.buildPageURL(cursor)
	if err != nil {
		return nil, "", fmt.Errorf("bbclient: build page URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("bbclient: build page request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("bbclient: page request: %w", err)
	}

	// Close body immediately after decoding — not deferred — so we don't
	// hold all response bodies open across the pagination loop.
	var page ballotPageResponse
	decodeErr := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes)).Decode(&page)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("bbclient: page request returned %s", resp.Status)
	}
	if decodeErr != nil {
		return nil, "", fmt.Errorf("bbclient: decode page response: %w", decodeErr)
	}

	return page.Data, page.Meta.Cursor, nil
}

// buildPageURL constructs the paginated board URL with limit and optional cursor.
func (c *BBClient) buildPageURL(cursor string) (string, error) {
	u, err := url.Parse(c.baseURL + "/api/v1/board")
	if err != nil {
		return "", err
	}

	q := u.Query()
	q.Set("limit", strconv.Itoa(c.pageLimit))
	if cursor != "" {
		q.Set("cursor", cursor)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}
