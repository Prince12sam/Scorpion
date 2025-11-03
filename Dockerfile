# Scorpion Security Platform - Production Docker Image
FROM node:18-alpine AS base

# Install system dependencies for security tools
RUN apk add --no-cache \
    nmap \
    curl \
    wget \
    openssl \
    ca-certificates \
    git \
    python3 \
    py3-pip \
    build-base \
    linux-headers

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

# Create necessary directories
RUN mkdir -p /app/results /app/reports /app/logs && \
    chown -R scorpion:scorpion /app

# Switch to non-root user
USER scorpion

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3001/api/health || exit 1

# Environment variables
ENV NODE_ENV=production
ENV PORT=3001
ENV HOST=0.0.0.0

# Expose port
EXPOSE 3001

# Start the application
CMD ["node", "server/simple-web-server.js"]