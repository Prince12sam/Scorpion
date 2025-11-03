# 🦂 Scorpion Security Platform - Docker Deployment Guide

## Quick Start with Docker

### Prerequisites
- Docker Engine 20.10+
- Docker Compose 2.0+
- 4GB+ RAM
- 10GB+ disk space

### One-Click Deployment

#### Windows
```bash
# Run the deployment script
./deploy.bat
```

#### Linux/macOS
```bash
# Make script executable
chmod +x deploy.sh

# Run deployment
./deploy.sh
```

### Manual Deployment

1. **Clone and Navigate**
   ```bash
   git clone <repository-url>
   cd Testing_Tool
   ```

2. **Build and Start**
   ```bash
   docker-compose up -d --build
   ```

3. **Access the Platform**
   - Web Interface: https://localhost
   - API: https://localhost/api/health
   - Default Login: admin/admin

## Architecture

### Services
- **scorpion-web**: Main application server
- **redis**: Session storage and caching
- **nginx**: Reverse proxy with SSL termination

### Ports
- `80`: HTTP (redirects to HTTPS)
- `443`: HTTPS (main interface)
- `3001`: Direct application access
- `6379`: Redis (internal)

## Performance Enhancements

### 🚀 Web Application Improvements

1. **Frontend Optimizations**
   - ✅ Gzip compression enabled
   - ✅ Static asset caching (1 year)
   - ✅ Code splitting ready
   - ✅ Lazy loading support

2. **Backend Enhancements**
   - ✅ Clustering support (multi-core)
   - ✅ Rate limiting (API & Auth)
   - ✅ Connection pooling
   - ✅ Memory optimization

3. **Security Improvements**
   - ✅ Enhanced CSP headers
   - ✅ HSTS enforcement
   - ✅ XSS protection
   - ✅ Rate limiting by IP

4. **Monitoring & Logging**
   - ✅ Health checks
   - ✅ Performance metrics
   - ✅ Error tracking
   - ✅ Access logs

## Configuration

### Environment Variables
```bash
# Core Settings
NODE_ENV=production
PORT=3001
HOST=0.0.0.0

# Security
JWT_SECRET=your-secret-key
ENABLE_HTTPS=true
RATE_LIMIT_MAX=100

# Performance
ENABLE_CLUSTERING=true
ENABLE_COMPRESSION=true
WORKER_PROCESSES=auto
```

### Volume Mounts
```yaml
volumes:
  - ./results:/app/results     # Scan results
  - ./reports:/app/reports     # Generated reports
  - ./logs:/app/logs          # Application logs
```

## Management Commands

### Service Management
```bash
# View status
docker-compose ps

# View logs
docker-compose logs -f

# Restart services
docker-compose restart

# Stop services
docker-compose down

# Update and rebuild
docker-compose down && docker-compose up -d --build
```

### Scaling
```bash
# Scale web service
docker-compose up -d --scale scorpion-web=3

# Monitor resource usage
docker stats
```

### Backup & Restore
```bash
# Backup data
docker run --rm -v scorpion_redis-data:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz -C /data .

# Restore data
docker run --rm -v scorpion_redis-data:/data -v $(pwd):/backup alpine tar xzf /backup/backup.tar.gz -C /data
```

## Security Features

### SSL/TLS
- Self-signed certificates generated automatically
- HTTPS-only mode with HSTS
- Modern cipher suites
- HTTP to HTTPS redirect

### Rate Limiting
- Authentication: 5 requests/15 minutes
- API endpoints: 100 requests/15 minutes
- IP-based blocking
- Burst protection

### Headers
- Content Security Policy
- X-Frame-Options: DENY
- X-Content-Type-Options: nosniff
- Referrer-Policy: strict-origin

## Monitoring

### Health Checks
```bash
# Application health
curl https://localhost/api/health

# Service status
docker-compose ps

# Resource usage
docker stats
```

### Logs
```bash
# Application logs
docker-compose logs scorpion-web

# Nginx access logs
docker-compose logs nginx

# Redis logs
docker-compose logs redis
```

## Troubleshooting

### Common Issues

1. **Port Already in Use**
   ```bash
   # Change ports in docker-compose.yml
   ports:
     - "8080:80"    # HTTP
     - "8443:443"   # HTTPS
   ```

2. **SSL Certificate Issues**
   ```bash
   # Regenerate certificates
   rm -rf ssl/
   mkdir ssl
   ./deploy.sh
   ```

3. **Performance Issues**
   ```bash
   # Increase resources
   docker-compose down
   # Edit docker-compose.yml to add:
   deploy:
     resources:
       limits:
         memory: 2G
         cpus: '2'
   ```

4. **Database Connection Issues**
   ```bash
   # Check Redis connection
   docker-compose exec redis redis-cli ping
   
   # Restart Redis
   docker-compose restart redis
   ```

### Debug Mode
```bash
# Run with debug output
DEBUG=* docker-compose up

# Access container shell
docker-compose exec scorpion-web sh
```

## Production Considerations

### Security Hardening
1. Change default credentials
2. Use strong JWT secrets
3. Configure firewall rules
4. Enable audit logging
5. Regular security updates

### Performance Optimization
1. Use external Redis cluster
2. Enable CDN for static assets
3. Configure load balancer
4. Monitor resource usage
5. Scale horizontally

### Monitoring Setup
1. Configure log aggregation
2. Set up alerting
3. Monitor metrics
4. Health check endpoints
5. Error tracking

## API Documentation

### Authentication
```bash
# Login
curl -X POST https://localhost/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# Get token
export TOKEN="your-jwt-token"

# Authenticated request
curl -H "Authorization: Bearer $TOKEN" \
  https://localhost/api/dashboard/metrics
```

### Security Scanning
```bash
# Start scan
curl -X POST https://localhost/api/scan \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"target":"example.com","type":"quick"}'

# Get results
curl https://localhost/api/scan/SCAN_ID \
  -H "Authorization: Bearer $TOKEN"
```

## Support

For issues and questions:
1. Check logs: `docker-compose logs`
2. Verify configuration
3. Review troubleshooting guide
4. Submit issue with logs and config