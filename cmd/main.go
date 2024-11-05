package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/iuriikogan-snyk/snyk-controller/pkg/snyk_client"
)


func init() {
	var err error
	// Initialize the logger
	logger = slog.New(slog.NewTextHandler(os.Stdout, slog.LevelInfo))

	// Load the configuration
	if err = LoadConfig(); err != nil {
		logger.Error("Failed to load configuration", slog.Any("error", err))
		os.Exit(1)
	}

	// Initialize the Snyk client
	client, err = (snykToken, snykOrgID, snykApiEndpoint)
	if err != nil {
		logger.Error("Failed to create Snyk client", slog.Any("error", err))
		os.Exit(1)
	}
}

func handleDeploymentCreate(deploymentName string, imageURL string) error {
	logger.Info("Processing deployment creation", slog.String("deployment", deploymentName), slog.String("image", imageURL))

	sbom, err := client.SBOM(context.Background(), imageURL)
	if err != nil {
		logger.Error("Error generating SBOM", slog.String("deployment", deploymentName), slog.Any("error", err))
		return err
	}

	if err = uploadSBOMAsArtifact(imageURL, sbom); err != nil {
		logger.Error("Error uploading SBOM", slog.Any("error", err))
		return err
	}

	logger.Info("SBOM and attestation successfully uploaded", slog.String("deployment", deploymentName))
	return nil
}

func handleDeploymentDelete(deploymentName string) error {
	logger.Info("Processing deployment deletion", slog.String("deployment", deploymentName))

	if err := client.ProjectDelete(context.Background(), deploymentName); err != nil {
		logger.Error("Error deleting Snyk project", slog.String("deployment", deploymentName), slog.Any("error", err))
		return err
	}

	logger.Info("Snyk project successfully deleted", slog.String("deployment", deploymentName))
	return nil
}

func main() {
	if err := handleDeploymentCreate("test-deployment", "docker.io/iuriikogan-snyk/nodejs-goof-insights:latest"); err != nil {
		logger.Error("Error processing deployment creation", slog.Any("error", err))
	}

	if err := handleDeploymentDelete("test-deployment"); err != nil {
		logger.Error("Error processing deployment deletion", slog.Any("error", err))
	}
}
