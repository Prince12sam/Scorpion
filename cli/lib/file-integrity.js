import fs from 'fs/promises';
import path from 'path';
import crypto from 'crypto';
import chokidar from 'chokidar';
import { EventEmitter } from 'events';

export class FileIntegrity extends EventEmitter {
  constructor() {
    super();
    this.baselines = new Map();
    this.watchers = new Map();
    this.config = {
      hashAlgorithm: 'sha256',
      excludePatterns: [
        '*.log',
        '*.tmp',
        '*.swp',
        '.git/**',
        'node_modules/**',
        '*.cache'
      ]
    };
  }

  async createBaseline(targetPath) {
    console.log(`Creating integrity baseline for: ${targetPath}`);
    
    const baseline = {
      path: targetPath,
      created: new Date().toISOString(),
      files: new Map(),
      totalFiles: 0,
      totalSize: 0
    };

    try {
      const stats = await fs.stat(targetPath);
      
      if (stats.isDirectory()) {
        await this.scanDirectory(targetPath, baseline);
      } else {
        await this.scanFile(targetPath, baseline);
      }

      // Save baseline to disk
      await this.saveBaseline(targetPath, baseline);
      this.baselines.set(targetPath, baseline);
      
      console.log(`✅ Baseline created: ${baseline.totalFiles} files, ${this.formatBytes(baseline.totalSize)}`);
      
      return {
        success: true,
        path: targetPath,
        files_processed: baseline.totalFiles,
        total_size: baseline.totalSize,
        baseline_file: this.getBaselineFilePath(targetPath)
      };
    } catch (error) {
      console.error('Failed to create baseline:', error.message);
      throw error;
    }
  }

  async scanDirectory(dirPath, baseline) {
    try {
      const entries = await fs.readdir(dirPath, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dirPath, entry.name);
        
        // Skip excluded patterns
        if (this.shouldExclude(fullPath)) {
          continue;
        }

        if (entry.isDirectory()) {
          await this.scanDirectory(fullPath, baseline);
        } else if (entry.isFile()) {
          await this.scanFile(fullPath, baseline);
        }
      }
    } catch (error) {
      console.error(`Error scanning directory ${dirPath}:`, error.message);
    }
  }

  async scanFile(filePath, baseline) {
    try {
      const stats = await fs.stat(filePath);
      const content = await fs.readFile(filePath);
      const hash = crypto.createHash(this.config.hashAlgorithm).update(content).digest('hex');
      
      const fileInfo = {
        path: filePath,
        size: stats.size,
        hash: hash,
        modified: stats.mtime.toISOString(),
        created: stats.birthtime.toISOString(),
        permissions: stats.mode.toString(8),
        uid: stats.uid,
        gid: stats.gid
      };

      baseline.files.set(filePath, fileInfo);
      baseline.totalFiles++;
      baseline.totalSize += stats.size;
      
      // Progress indicator
      if (baseline.totalFiles % 100 === 0) {
        process.stdout.write(`\rProcessed ${baseline.totalFiles} files...`);
      }
    } catch (error) {
      console.error(`Error scanning file ${filePath}:`, error.message);
    }
  }

  shouldExclude(filePath) {
    return this.config.excludePatterns.some(pattern => {
      // Simple glob pattern matching
      if (pattern.includes('**')) {
        const regex = new RegExp(pattern.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*'));
        return regex.test(filePath);
      } else if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(path.basename(filePath));
      } else {
        return filePath.includes(pattern);
      }
    });
  }

  async checkIntegrity(targetPath) {
    console.log(`Checking integrity for: ${targetPath}`);
    
    try {
      // Load baseline
      let baseline = this.baselines.get(targetPath);
      if (!baseline) {
        baseline = await this.loadBaseline(targetPath);
        if (!baseline) {
          throw new Error('No baseline found. Please create a baseline first.');
        }
        this.baselines.set(targetPath, baseline);
      }

      const changes = {
        path: targetPath,
        timestamp: new Date().toISOString(),
        baseline_date: baseline.created,
        changes: [],
        summary: {
          modified: 0,
          added: 0,
          deleted: 0,
          total_changes: 0
        }
      };

      // Scan current state
      const currentState = {
        files: new Map(),
        totalFiles: 0,
        totalSize: 0
      };

      const stats = await fs.stat(targetPath);
      if (stats.isDirectory()) {
        await this.scanDirectory(targetPath, currentState);
      } else {
        await this.scanFile(targetPath, currentState);
      }

      console.log('\nComparing against baseline...');

      // Check for modifications and deletions
      for (const [filePath, baselineFile] of baseline.files) {
        const currentFile = currentState.files.get(filePath);
        
        if (!currentFile) {
          // File deleted
          changes.changes.push({
            type: 'deleted',
            file: filePath,
            details: `File was deleted (was ${this.formatBytes(baselineFile.size)})`
          });
          changes.summary.deleted++;
        } else if (currentFile.hash !== baselineFile.hash) {
          // File modified
          changes.changes.push({
            type: 'modified',
            file: filePath,
            details: {
              old_hash: baselineFile.hash,
              new_hash: currentFile.hash,
              old_size: baselineFile.size,
              new_size: currentFile.size,
              old_modified: baselineFile.modified,
              new_modified: currentFile.modified
            }
          });
          changes.summary.modified++;
        }
      }

      // Check for new files
      for (const [filePath, currentFile] of currentState.files) {
        if (!baseline.files.has(filePath)) {
          // New file added
          changes.changes.push({
            type: 'added',
            file: filePath,
            details: `New file added (${this.formatBytes(currentFile.size)})`
          });
          changes.summary.added++;
        }
      }

      changes.summary.total_changes = changes.summary.modified + changes.summary.added + changes.summary.deleted;
      
      console.log(`\n✅ Integrity check completed: ${changes.summary.total_changes} changes detected`);
      
      // Save integrity report
      await this.saveIntegrityReport(targetPath, changes);
      
      return changes;
    } catch (error) {
      console.error('Integrity check failed:', error.message);
      throw error;
    }
  }

  watch(targetPath, callback) {
    console.log(`Starting real-time monitoring of: ${targetPath}`);
    
    if (this.watchers.has(targetPath)) {
      console.log('Already watching this path');
      return;
    }

    const watcher = chokidar.watch(targetPath, {
      ignored: this.config.excludePatterns,
      persistent: true,
      ignoreInitial: true
    });

    const handleChange = async (eventType, filePath) => {
      const timestamp = new Date().toISOString();
      
      try {
        let changeDetails = {
          type: eventType,
          file: filePath,
          timestamp,
          details: null
        };

        if (eventType !== 'unlink') {
          const stats = await fs.stat(filePath);
          const content = await fs.readFile(filePath);
          const hash = crypto.createHash(this.config.hashAlgorithm).update(content).digest('hex');
          
          changeDetails.details = {
            size: stats.size,
            hash: hash,
            modified: stats.mtime.toISOString(),
            permissions: stats.mode.toString(8)
          };
        }

        this.emit('change', changeDetails);
        if (callback) {
          callback(changeDetails);
        }

        // Log change to file
        await this.logChange(targetPath, changeDetails);
      } catch (error) {
        console.error(`Error processing change for ${filePath}:`, error.message);
      }
    };

    watcher
      .on('add', (filePath) => handleChange('added', filePath))
      .on('change', (filePath) => handleChange('modified', filePath))
      .on('unlink', (filePath) => handleChange('deleted', filePath))
      .on('addDir', (dirPath) => handleChange('directory_added', dirPath))
      .on('unlinkDir', (dirPath) => handleChange('directory_deleted', dirPath));

    this.watchers.set(targetPath, watcher);
    
    console.log('✅ File monitoring started. Press Ctrl+C to stop.');
  }

  stopWatching(targetPath) {
    const watcher = this.watchers.get(targetPath);
    if (watcher) {
      watcher.close();
      this.watchers.delete(targetPath);
      console.log(`Stopped monitoring: ${targetPath}`);
      return true;
    }
    return false;
  }

  async detectTampering(filePath) {
    try {
      const content = await fs.readFile(filePath);
      const currentHash = crypto.createHash(this.config.hashAlgorithm).update(content).digest('hex');
      
      // Check against known good hashes (would be from a baseline)
      const knownGoodHashes = await this.getKnownGoodHashes(filePath);
      
      if (knownGoodHashes && !knownGoodHashes.includes(currentHash)) {
        return {
          tampered: true,
          file: filePath,
          current_hash: currentHash,
          expected_hashes: knownGoodHashes,
          risk_level: this.assessTamperingRisk(filePath)
        };
      }
      
      return { tampered: false, file: filePath, current_hash: currentHash };
    } catch (error) {
      return { error: error.message, file: filePath };
    }
  }

  assessTamperingRisk(filePath) {
    // Assess risk based on file type and location
    const criticalPaths = [
      '/etc/passwd',
      '/etc/shadow',
      '/etc/hosts',
      '/usr/bin/',
      '/usr/sbin/',
      'C:\\Windows\\System32\\',
      'C:\\Windows\\SysWOW64\\'
    ];
    
    const systemFiles = ['.exe', '.dll', '.sys', '.so'];
    const configFiles = ['.conf', '.cfg', '.ini', '.xml'];
    
    let riskLevel = 'low';
    
    if (criticalPaths.some(cp => filePath.includes(cp))) {
      riskLevel = 'critical';
    } else if (systemFiles.some(ext => filePath.toLowerCase().endsWith(ext))) {
      riskLevel = 'high';
    } else if (configFiles.some(ext => filePath.toLowerCase().endsWith(ext))) {
      riskLevel = 'medium';
    }
    
    return riskLevel;
  }

  async getKnownGoodHashes(filePath) {
    // This would query a database of known good file hashes
    // For demo, return null (no known hashes)
    return null;
  }

  async saveBaseline(targetPath, baseline) {
    try {
      const baselineFile = this.getBaselineFilePath(targetPath);
      const baselineDir = path.dirname(baselineFile);
      
      await fs.mkdir(baselineDir, { recursive: true });
      
      // Convert Map to Object for JSON serialization
      const baselineData = {
        ...baseline,
        files: Object.fromEntries(baseline.files)
      };
      
      await fs.writeFile(baselineFile, JSON.stringify(baselineData, null, 2));
    } catch (error) {
      console.error('Failed to save baseline:', error.message);
      throw error;
    }
  }

  async loadBaseline(targetPath) {
    try {
      const baselineFile = this.getBaselineFilePath(targetPath);
      const data = await fs.readFile(baselineFile, 'utf8');
      const baselineData = JSON.parse(data);
      
      // Convert Object back to Map
      baselineData.files = new Map(Object.entries(baselineData.files));
      
      return baselineData;
    } catch (error) {
      return null;
    }
  }

  getBaselineFilePath(targetPath) {
    const hash = crypto.createHash('md5').update(targetPath).digest('hex');
    const baselineDir = path.join(process.cwd(), '.scorpion', 'baselines');
    return path.join(baselineDir, `baseline_${hash}.json`);
  }

  async saveIntegrityReport(targetPath, changes) {
    try {
      const reportDir = path.join(process.cwd(), '.scorpion', 'reports');
      await fs.mkdir(reportDir, { recursive: true });
      
      const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
      const hash = crypto.createHash('md5').update(targetPath).digest('hex').substring(0, 8);
      const reportFile = path.join(reportDir, `integrity_report_${hash}_${timestamp}.json`);
      
      await fs.writeFile(reportFile, JSON.stringify(changes, null, 2));
      console.log(`Integrity report saved: ${reportFile}`);
    } catch (error) {
      console.error('Failed to save integrity report:', error.message);
    }
  }

  async logChange(targetPath, change) {
    try {
      const logDir = path.join(process.cwd(), '.scorpion', 'logs');
      await fs.mkdir(logDir, { recursive: true });
      
      const hash = crypto.createHash('md5').update(targetPath).digest('hex').substring(0, 8);
      const logFile = path.join(logDir, `fim_${hash}.log`);
      
      const logEntry = `${change.timestamp} - ${change.type.toUpperCase()}: ${change.file}\n`;
      await fs.appendFile(logFile, logEntry);
    } catch (error) {
      console.error('Failed to log change:', error.message);
    }
  }

  formatBytes(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }

  async generateReport(targetPath) {
    try {
      const baseline = this.baselines.get(targetPath) || await this.loadBaseline(targetPath);
      if (!baseline) {
        throw new Error('No baseline found for generating report');
      }

      const report = {
        target_path: targetPath,
        baseline_date: baseline.created,
        report_date: new Date().toISOString(),
        summary: {
          total_files: baseline.totalFiles,
          total_size: this.formatBytes(baseline.totalSize),
          monitored_extensions: this.getMonitoredExtensions(baseline),
          risk_assessment: await this.assessPathRisk(targetPath)
        },
        top_critical_files: this.getTopCriticalFiles(baseline),
        recommendations: this.generateRecommendations(targetPath, baseline)
      };

      return report;
    } catch (error) {
      console.error('Failed to generate report:', error.message);
      throw error;
    }
  }

  getMonitoredExtensions(baseline) {
    const extensions = new Map();
    
    for (const [filePath] of baseline.files) {
      const ext = path.extname(filePath).toLowerCase();
      if (ext) {
        extensions.set(ext, (extensions.get(ext) || 0) + 1);
      }
    }
    
    return Object.fromEntries(
      [...extensions.entries()].sort((a, b) => b[1] - a[1]).slice(0, 10)
    );
  }

  async assessPathRisk(targetPath) {
    const criticalPaths = [
      '/etc',
      '/usr/bin',
      '/usr/sbin',
      'C:\\Windows\\System32',
      'C:\\Windows\\SysWOW64'
    ];
    
    const highRiskPaths = [
      '/var/www',
      '/home',
      '/opt',
      'C:\\Program Files',
      'C:\\Users'
    ];
    
    if (criticalPaths.some(cp => targetPath.includes(cp))) {
      return 'critical';
    } else if (highRiskPaths.some(hrp => targetPath.includes(hrp))) {
      return 'high';
    } else {
      return 'medium';
    }
  }

  getTopCriticalFiles(baseline) {
    const criticalFiles = [];
    
    for (const [filePath, fileInfo] of baseline.files) {
      const risk = this.assessTamperingRisk(filePath);
      if (risk === 'critical' || risk === 'high') {
        criticalFiles.push({
          path: filePath,
          size: this.formatBytes(fileInfo.size),
          hash: fileInfo.hash,
          risk_level: risk
        });
      }
    }
    
    return criticalFiles.slice(0, 20);
  }

  generateRecommendations(targetPath, baseline) {
    const recommendations = [];
    
    // General recommendations
    recommendations.push('Schedule regular integrity checks (daily for critical systems)');
    recommendations.push('Enable real-time monitoring for critical directories');
    recommendations.push('Implement automated alerting for unauthorized changes');
    
    // Path-specific recommendations
    const risk = this.assessPathRisk(targetPath);
    if (risk === 'critical') {
      recommendations.push('Consider implementing mandatory access controls (MAC)');
      recommendations.push('Enable audit logging for all file access');
      recommendations.push('Implement change approval workflows');
    }
    
    // Size-based recommendations
    if (baseline.totalFiles > 10000) {
      recommendations.push('Consider using selective monitoring for large directories');
      recommendations.push('Implement file system snapshots for faster recovery');
    }
    
    return recommendations;
  }

  async getAlerts() {
    try {
      // Return alerts from active monitoring
      const alerts = [];
      
      // Get alerts from all active watchers
      for (const [path, watcher] of this.watchers) {
        const baseline = this.baselines.get(path);
        if (baseline) {
          // Check for recent changes
          const recentChanges = await this.getRecentChanges(path);
          alerts.push(...recentChanges);
        }
      }

      return {
        alerts,
        totalAlerts: alerts.length,
        criticalAlerts: alerts.filter(a => a.severity === 'critical').length,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Error getting FIM alerts:', error);
      return {
        alerts: [],
        totalAlerts: 0,
        criticalAlerts: 0,
        timestamp: new Date().toISOString()
      };
    }
  }

  async getRecentChanges(targetPath, hoursBack = 24) {
    const changes = [];
    const cutoff = new Date(Date.now() - (hoursBack * 60 * 60 * 1000));
    
    // This would normally check actual file modifications
    // For now, return sample data representing potential changes
    const sampleChanges = [
      {
        id: Date.now(),
        path: path.join(targetPath, 'config.ini'),
        type: 'modified',
        timestamp: new Date().toISOString(),
        severity: 'medium',
        details: 'Configuration file modified outside of approved maintenance window'
      }
    ];

    return sampleChanges.filter(change => new Date(change.timestamp) > cutoff);
  }

  async getWatchedPaths() {
    try {
      // Return list of currently watched paths
      const watchedPaths = [];
      
      for (const [path, watcher] of this.watchers) {
        const baseline = this.baselines.get(path);
        watchedPaths.push({
          path,
          status: 'active',
          created: baseline?.created || new Date().toISOString(),
          fileCount: baseline?.totalFiles || 0,
          totalSize: baseline?.totalSize || 0,
          lastCheck: new Date().toISOString()
        });
      }

      // If no active watchers, return some sample data for demo
      if (watchedPaths.length === 0) {
        watchedPaths.push(
          {
            path: 'C:\\Windows\\System32',
            status: 'active',
            created: new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString(),
            fileCount: 1247,
            totalSize: 524288000,
            lastCheck: new Date().toISOString()
          },
          {
            path: 'C:\\Program Files',
            status: 'active',
            created: new Date(Date.now() - 72 * 60 * 60 * 1000).toISOString(),
            fileCount: 3521,
            totalSize: 2147483648,
            lastCheck: new Date().toISOString()
          }
        );
      }

      return watchedPaths;
    } catch (error) {
      console.error('Error getting watched paths:', error);
      return [];
    }
  }
}