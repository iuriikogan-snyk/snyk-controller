package snykclient

import (
	"context"
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
		baseURL: snykApiEndpoint, // Snyk API base URL
	}
}

func (c *snykClient) SBOM(ctx context.Context, imageURL string) ([]bytes, error) {
	// TODO implement SBOM method
}

func (c *snykClient) Monitor(ctx context.Context, imageURL string) (projectId string, error) {
	// TODO implement Monitor method
}

func (c *snykClient) ProjectDelete(ctx context.Context, imageURL string, projectId string) error {
	// TODO implement ProjectDelete
}
