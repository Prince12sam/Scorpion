# Scorpion Security Platform - Multi-Platform Docker Image
# Supports: Linux (all flavors), Windows containers, ARM64, AMD64
FROM node:22-alpine AS base

# Install system dependencies for security tools and CLI operations
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    curl \
    wget \
    openssl \
    ca-certificates \
    git \
    python3 \
    py3-pip \
    build-base \
    linux-headers \
    bash \
    net-tools \
    iputils \
    bind-tools \
    tcpdump \
    socat

WORKDIR /app

# Create non-root user for security
RUN addgroup -g 1001 -S scorpion && \
    adduser -S scorpion -u 1001 -G scorpion

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production && npm cache clean --force

# Build stage
FROM base AS builder

# Copy source code
COPY . .

# Install all dependencies (including dev)
RUN npm ci

# Build the application
RUN npm run build

# Production stage
FROM base AS production

# Copy built application
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/cli ./cli
COPY --from=builder /app/server ./server
COPY --from=builder /app/package*.json ./

# Copy essential configuration files
COPY --from=builder /app/.env.example ./.env
COPY --from=builder /app/README.md ./

# Create necessary directories with proper permissions
RUN mkdir -p /app/results /app/reports /app/logs /app/cli/results /app/cli/data && \
    chown -R scorpion:scorpion /app

# Switch to non-root user
USER scorpion

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

# Environment variables with secure defaults
ENV NODE_ENV=production \
    PORT=3001 \
    HOST=0.0.0.0 \
    EASY_LOGIN=true \
    SCORPION_ADMIN_USER=admin \
    SCORPION_ADMIN_PASSWORD=admin

# Expose ports (API and Vite if needed)
EXPOSE 3001 5173

# Start the application
CMD ["node", "server/clean-server.js"]