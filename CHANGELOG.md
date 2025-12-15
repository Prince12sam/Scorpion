# Changelog

All notable changes to the Scorpion CLI Security Tool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-12-08

### 🎉 Major Release - CLI-Only Focus

This is a major breaking release that removes all web interface components and focuses exclusively on the CLI tool.

### Removed 🗑️
- **Web Interface**: Removed entire React frontend application
- **Web Server**: Removed Express.js API server and all endpoints
- **Frontend Dependencies**: React, React-DOM, Vite, Tailwind CSS, PostCSS, Radix UI components
- **Server Dependencies**: Express, Helmet, CORS, JWT, bcrypt, session management, WebSocket server
- **Database Components**: Prisma, Redis clients
- **Docker Setup**: Docker files and container configurations
- **Web Documentation**: Docker guides, deployment guides, web interface documentation
- **Test Files**: All web interface test files and HTML test pages
- **Deployment Scripts**: All web server startup and deployment scripts

### Changed 🔄
- **Project Name**: `scorpion-security-platform` → `scorpion-cli`
- **Description**: Updated to reflect CLI-only focus
- **Dependencies**: Reduced from 93 to 8 core dependencies (91% reduction)
- **Installation Size**: Reduced from ~450 MB to ~30 MB (93% reduction)
- **Scripts**: Removed all web-related npm scripts, kept only CLI commands
- **Documentation**: Completely rewritten README.md for CLI usage only

### Added ✨
- **Installation Scripts**: Simple `install.sh` for easy setup on Linux/macOS
- **Quick Start Guide**: New QUICKSTART.md with common usage examples
- **Migration Guide**: MIGRATION.md explaining changes from v1.x to v2.0
- **Streamlined Structure**: Clean project structure focused on CLI functionality

### Security 🔒
- **Eliminated Web Vulnerabilities**: No more Express, JWT, or React-related security issues
- **Reduced Attack Surface**: Removed all web-based attack vectors
- **Zero Critical Vulnerabilities**: Clean npm audit with no vulnerabilities
- **Simpler Security Model**: No authentication, sessions, or web server to secure

### Performance ⚡
- **Faster Installation**: 93% smaller installation size
- **Instant Startup**: No web server initialization
- **Lower Memory**: Minimal runtime footprint
- **Better for Automation**: Perfect for CI/CD and scripting

### Breaking Changes ⚠️
- **No Web Interface**: All functionality now CLI-only
- **No API Server**: Cannot start web server with `scorpion web` command
- **No Browser Access**: No web dashboard or UI
- **Configuration Changes**: Removed web-specific environment variables

## [1.0.1] - 2025-11-02

### Added
- Comprehensive OWASP Top 10 testing
- Advanced stealth capabilities
- Enterprise vulnerability scanning
- AI-powered autonomous pentesting
- File integrity monitoring
- Password security suite

### Changed
- Enhanced security hardening
- Improved documentation
- Better cross-platform support

### Security
- Implemented SSRF protection
- Added input validation
- Enhanced rate limiting
- Secure hash functions

## [1.0.0] - 2025-10-15

### Added
- Initial release
- Basic vulnerability scanning
- Network reconnaissance
- Web interface
- CLI tool
- Threat intelligence integration

---

## Migration from v1.x to v2.0

If you were using version 1.x with the web interface, please read [MIGRATION.md](MIGRATION.md) for detailed migration instructions.

**TL;DR**: All web interface functionality has been removed. Use CLI commands instead.

---

[2.0.0]: https://github.com/Prince12sam/Scorpion/releases/tag/v2.0.0
[1.0.1]: https://github.com/Prince12sam/Scorpion/releases/tag/v1.0.1
[1.0.0]: https://github.com/Prince12sam/Scorpion/releases/tag/v1.0.0
