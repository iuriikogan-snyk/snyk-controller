package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"oras.land/oras-go/v2"
)

var (
	logger      *slog.Logger
	snykToken   string
	snykOrgID   string
	registryUrl string // Use registryUrl instead of ociRegistry
)

func init() {
	logger = slog.New(slog.NewTextHandler(os.Stdout, slog.LevelInfo)) // Initialize the logger

	err := LoadConfig()
	if err != nil {
		logger.Error("Failed to load config", slog.Any("error", err))
		os.Exit(1) // Exit the application on config load failure
	}
	// TODO define client factory
	snykApiClient := http.Client
}

func handleDeploymentCreate(deploymentName string, imageURL string) error {
	logger.Info("Processing deployment creation", slog.String("deployment", deploymentName), slog.String("image", imageURL))

	sbom, err := client.SBOM(context.Background(), imageURL)
	if err != nil {
		logger.Error("Error generating SBOM", slog.String("deployment", deploymentName), slog.Any("error", err))
		return err
	}

	uploadErr := uploadSBOMAsArtifact(imageURL, sbom)
	if uploadErr != nil {
		logger.Error("Error uploading SBOM", slog.Any("error", uploadErr))
		return uploadErr
	}

	logger.Info("SBOM and attestation successfully uploaded", slog.String("deployment", deploymentName))
	return nil
}

func handleDeploymentDelete(deploymentName string) error {
	logger.Info("Processing deployment deletion", slog.String("deployment", deploymentName))

	err := client.ProjectDelete(context.Background(), deploymentName)
	if err != nil {
		logger.Error("Error deleting Snyk project", slog.String("deployment", deploymentName), slog.Any("error", err))
		return err
	}

	logger.Info("Snyk project successfully deleted", slog.String("deployment", deploymentName))
	return nil
}

func uploadSBOMAsArtifact(imageURL string, sbom []byte) error {
	logger.Info("Uploading SBOM to registry", slog.String("imageURL", imageURL))

	artifactRef := fmt.Sprintf("%s:%s", imageURL, "sbom")

	orasClient, err := oras.NewClient(oras.WithLogger(os.Stdout))
	if err != nil {
		return fmt.Errorf("failed to create ORAS client: %w", err)
	}

	files := []oras.File{
		{
			Path: "bom.spdx.json",
			Data: sbom,
		},
	}

	_, err = orasClient.Push(context.Background(), artifactRef, registryUrl, files,
		oras.WithConfigMediaType("application/vnd.snyk.sbom+json"),
		oras.WithName("sbom.json"),
	)
	if err != nil {
		return fmt.Errorf("failed to push SBOM artifact: %w", err)
	}

	logger.Info("SBOM artifact successfully uploaded", slog.String("artifactRef", artifactRef))
	return nil
}

func main() {
	err := handleDeploymentCreate("test-deployment", "docker.io/iuriikogan-snyk/nodejs-goof-insights:latest")
	if err != nil {
		logger.Error("Error processing deployment create", slog.Any("error", err))
	}

	err = handleDeploymentDelete("test-deployment")
	if err != nil {
		logger.Error("Error processing deployment delete", slog.Any("error", err))
	}
}
