// snyk_client.go
package snykclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

type Client interface {
	SBOM(ctx context.Context, imageURL string) ([]byte, error)
	ProjectDelete(ctx context.Context, projectName string) error
}

type snykClient struct {
	token   string
	orgID   string
	baseURL string
}

func NewClient(token, orgID string) Client {
	return &snykClient{
		token:   token,
		orgID:   orgID,
		baseURL: "https://snyk.io/api/v1", // Snyk API base URL
	}
}

func (c *snykClient) SBOM(ctx context.Context, imageURL string) ([]byte, error) {
	// Replace with actual logic to generate SBOM from the Snyk API
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/sboms", c.baseURL), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "token "+c.token)
	req.Header.Set("Content-Type", "application/json")

	// Example payload for SBOM generation
	payload := map[string]string{"image": imageURL}
	body, _ := json.Marshal(payload)
	req.Body = io.NopCloser(bytes.NewReader(body))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to generate SBOM: %s", resp.Status)
	}

	return io.ReadAll(resp.Body)
}

func (c *snykClient) ProjectDelete(ctx context.Context, projectName string) error {
	req, err := http.NewRequestWithContext(ctx, "DELETE", fmt.Sprintf("%s/projects/%s", c.baseURL, projectName), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+c.token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to delete project: %s", resp.Status)
	}

	return nil
}
