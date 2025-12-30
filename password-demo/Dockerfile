# Build stage
# NOTE: Build context must be the PROJECT ROOT (not password-demo/)
# so that we can access both password-demo/* and pir/* directories.
# In Railway: set Root Directory to "/" or leave empty, and set dockerfilePath to "password-demo/Dockerfile"
FROM rust:1.83-slim-bookworm AS builder

# Cache bust: force rebuild after removing conflicting railway.toml
# Build timestamp: 2024-12-29-2150
ARG CACHEBUST=3

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy all required crates (server depends on hibp and pir via path)
# With build context at project root:
COPY pir ./pir
COPY password-demo/hibp ./password-demo/hibp
COPY password-demo/server ./password-demo/server

WORKDIR /app/password-demo/server

# Build release binary
RUN cargo build --release

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/password-demo/server/target/release/hibp-server /app/hibp-server

# Create data directory (used when loading from files)
RUN mkdir -p /app/data/ranges

# Environment variables (defaults)
ENV HIBP_DATA_DIR=/app/data/ranges
ENV PORT=3000
ENV HIBP_MEMORY_MODE=true
ENV RUST_LOG=info

# HIBP_DOWNLOAD_ON_START: Set at runtime to download data on startup
#   docker run -e HIBP_DOWNLOAD_ON_START=tiny ...   # 256 ranges, ~20MB, ~2s
#   docker run -e HIBP_DOWNLOAD_ON_START=sample ... # 65k ranges, ~2.5GB, ~5min  
#   docker run -e HIBP_DOWNLOAD_ON_START=full ...   # 1M ranges, ~38GB, ~15min
# If not set, server loads from HIBP_DATA_DIR instead

EXPOSE 3000

CMD ["/app/hibp-server"]

