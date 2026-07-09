# Multi-stage build for Phantom Grid
# Build stage: Compile Go code and eBPF programs
FROM golang:1.21-bullseye AS builder

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    make \
    git \
    gcc-multilib \
    linux-libc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Generate eBPF bindings and build binaries
RUN make generate build

# Runtime stage: Minimal image with only binaries
FROM debian:bullseye-slim

# Install runtime dependencies for eBPF
RUN apt-get update && apt-get install -y \
    libbpf1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binaries from builder
COPY --from=builder /build/bin/phantom-grid /app/phantom-grid
COPY --from=builder /build/bin/spa-client /app/spa-client

# Create logs directory
RUN mkdir -p /app/logs

# Set permissions
RUN chmod +x /app/phantom-grid /app/spa-client

# Default command
CMD ["/app/phantom-grid"]

