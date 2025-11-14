# Makefile for building linkinfo for multiple platforms
#
# This Makefile builds the CLI located in ./cmd/linkinfo for:
#   - Linux:   386, amd64, arm, arm64
#   - macOS:   amd64, arm64
#   - Windows: 386, amd64
#
# All binaries are written to the ./dist directory with the pattern:
#   dist/linkinfo-<os>-<arch>[-.exe]


BINARY_NAME := linkinfo
CMD_DIR     := ./cmd/linkinfo
DIST_DIR    := dist

# Build metadata (used to populate -v output)
LDFLAGS := -X main.BuildTime="$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")" -X main.GitCommit="$(shell git rev-parse --short HEAD)"

.PHONY: all linux windows mac clean

# Build everything
all: linux windows mac

# Linux targets (32-bit, 64-bit, ARM)
linux: linux-amd64 linux-386 linux-arm linux-arm64

linux-amd64: $(DIST_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)

linux-386: $(DIST_DIR)
	GOOS=linux GOARCH=386 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-386 $(CMD_DIR)

linux-arm: $(DIST_DIR)
	GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm $(CMD_DIR)

linux-arm64: $(DIST_DIR)
	GOOS=linux GOARCH=arm64 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)

# macOS (darwin) targets
# On Apple Silicon we usually only build darwin-arm64 by default.
mac: darwin-arm64

darwin-amd64: $(DIST_DIR)
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)

darwin-arm64: $(DIST_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)

# Windows targets (32-bit, 64-bit)
windows: windows-amd64 windows-386

windows-amd64: $(DIST_DIR)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)

# Build for the current host platform (handy on dev machines)
.PHONY: native
native: $(DIST_DIR)
	CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME) $(CMD_DIR)

windows-386: $(DIST_DIR)
	GOOS=windows GOARCH=386 CGO_ENABLED=1 go build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(BINARY_NAME)-windows-386.exe $(CMD_DIR)

# Ensure dist directory exists
$(DIST_DIR):
	mkdir -p $(DIST_DIR)

# Remove build artifacts
clean:
	rm -rf $(DIST_DIR)
