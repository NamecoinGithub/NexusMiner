# Multi-stage Dockerfile for NexusMiner
# Stage 1: Build
FROM ubuntu:24.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    libgmp-dev \
    libboost-all-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build NexusMiner (basic hash mining, no GPU)
RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Stage 2: Runtime
FROM ubuntu:24.04

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    libssl3 \
    libgmp10 \
    libboost-system1.83.0 \
    && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /build/build/NexusMiner /usr/local/bin/

# Copy example config
COPY miner.conf /app/miner.conf

# Set working directory
WORKDIR /app

# Run NexusMiner
ENTRYPOINT ["NexusMiner"]
CMD ["miner.conf"]
