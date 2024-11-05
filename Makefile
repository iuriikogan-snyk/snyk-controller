# Variables
DOCKER_IMAGE = iuriikogan/snyk-controller
DOCKER_TAG = latest
DOCKERFILE = Dockerfile
APP_NAME = snyk-controller
BUILD_DIR = ./build

# Commands
GO_CMD = go
DOCKER_CMD = docker

# Default target
.PHONY: all
all: build

# Build the Go application
.PHONY: build
build:
	@echo "Building Go application..."
	mkdir -p $(BUILD_DIR)
	$(GO_CMD) build -o $(BUILD_DIR)/$(APP_NAME) ./main.go

# Build the Docker image
.PHONY: docker-build
docker-build: build
	@echo "Building Docker image..."
	$(DOCKER_CMD) build -t $(DOCKER_IMAGE):$(DOCKER_TAG) -f $(DOCKERFILE) .

# Run the application locally
.PHONY: run
run: build
	@echo "Running application locally..."
	./$(BUILD_DIR)/$(APP_NAME)

# Push the Docker image to the container registry
.PHONY: push
push: docker-build
	@echo "Pushing Docker image to registry..."
	$(DOCKER_CMD) push $(DOCKER_IMAGE):$(DOCKER_TAG)

# Clean the build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR)/$(APP_NAME)

# Print help
.PHONY: help
help:
	@echo "Makefile for snyk-controller"
	@echo ""
	@echo "Usage:"
	@echo "  make build         - Build the Go application"
	@echo "  make docker-build   - Build the Docker image"
	@echo "  make run          - Run the application locally"
	@echo "  make push         - Push the Docker image to the registry"
	@echo "  make clean        - Clean the build artifacts"
	@echo "  make help         - Show this help message"
