#!/usr/bin/env node

/**
 * 🦂 Scorpion Platform Startup Test
 * Cross-platform startup validation and system check
 */

import { spawn, exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import http from 'http';

const execAsync = promisify(exec);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

class StartupValidator {
  constructor() {
    this.platform = process.platform;
    this.arch = process.arch;
    this.nodeVersion = process.version;
    this.results = {
      platform: this.platform,
      arch: this.arch,
      nodeVersion: this.nodeVersion,
      tests: [],
      startTime: new Date().toISOString(),
      success: false
    };
  }

  log(message, type = 'info') {
    const timestamp = new Date().toISOString();
    const symbols = { info: '🔍', success: '✅', error: '❌', warning: '⚠️' };
    console.log(`${symbols[type]} [${timestamp}] ${message}`);
  }

  async testSystemRequirements() {
    this.log('Testing system requirements...', 'info');
    
    try {
      // Test Node.js version
      const majorVersion = parseInt(this.nodeVersion.slice(1).split('.')[0]);
      if (majorVersion < 16) {
        throw new Error(`Node.js version ${this.nodeVersion} is too old. Minimum required: 16.x`);
      }
      this.results.tests.push({ name: 'Node.js Version', status: 'passed', details: this.nodeVersion });
      this.log(`Node.js version ${this.nodeVersion} meets requirements`, 'success');

      // Test file system permissions
      const testFile = path.join(__dirname, 'test-write-permission.tmp');
      await fs.writeFile(testFile, 'test');
      await fs.unlink(testFile);
      this.results.tests.push({ name: 'File System Permissions', status: 'passed' });
      this.log('File system permissions validated', 'success');

      // Test memory
      const memUsage = process.memoryUsage();
      const memMB = Math.round(memUsage.rss / 1024 / 1024);
      this.results.tests.push({ 
        name: 'Memory Usage', 
        status: 'passed', 
        details: `${memMB}MB RSS` 
      });
      this.log(`Memory usage: ${memMB}MB RSS`, 'success');

      return true;
    } catch (error) {
      this.results.tests.push({ 
        name: 'System Requirements', 
        status: 'failed', 
        error: error.message 
      });
      this.log(`System requirements check failed: ${error.message}`, 'error');
      return false;
    }
  }

  async testPlatformScripts() {
    this.log('Testing platform-specific startup scripts...', 'info');
    
    try {
      let scriptToTest;
      let scriptExists = false;

      if (this.platform === 'win32') {
        scriptToTest = path.join(__dirname, 'start-windows.bat');
        try {
          await fs.access(scriptToTest);
          scriptExists = true;
        } catch {
          // Try alternative names
          const alternatives = ['start-scorpion.bat', 'launch-scorpion.bat'];
          for (const alt of alternatives) {
            try {
              await fs.access(path.join(__dirname, alt));
              scriptToTest = path.join(__dirname, alt);
              scriptExists = true;
              break;
            } catch {}
          }
        }
      } else {
        scriptToTest = path.join(__dirname, 'start-unix.sh');
        try {
          await fs.access(scriptToTest);
          scriptExists = true;
        } catch {
          // Unix systems might not have generated script
          this.log('Unix startup script not found, will use npm start', 'warning');
        }
      }

      this.results.tests.push({ 
        name: 'Platform Script Exists', 
        status: scriptExists ? 'passed' : 'warning',
        details: scriptExists ? scriptToTest : 'Using npm start fallback'
      });

      if (scriptExists) {
        this.log(`Platform script found: ${scriptToTest}`, 'success');
      } else {
        this.log('Platform script not found, using npm start', 'warning');
      }

      return true;
    } catch (error) {
      this.results.tests.push({ 
        name: 'Platform Scripts', 
        status: 'failed', 
        error: error.message 
      });
      this.log(`Platform script test failed: ${error.message}`, 'error');
      return false;
    }
  }

  async testPackageJson() {
    this.log('Testing package.json and dependencies...', 'info');
    
    try {
      const packagePath = path.join(__dirname, 'package.json');
      const packageData = JSON.parse(await fs.readFile(packagePath, 'utf8'));
      
      // Check required fields
      const requiredFields = ['name', 'version', 'scripts', 'dependencies'];
      for (const field of requiredFields) {
        if (!packageData[field]) {
          throw new Error(`Missing required field in package.json: ${field}`);
        }
      }

      // Check required scripts
      const requiredScripts = ['start', 'dev'];
      for (const script of requiredScripts) {
        if (!packageData.scripts[script]) {
          this.log(`Missing script in package.json: ${script}`, 'warning');
        }
      }

      // Check if node_modules exists
      try {
        await fs.access(path.join(__dirname, 'node_modules'));
        this.results.tests.push({ name: 'Dependencies Installed', status: 'passed' });
        this.log('Dependencies are installed', 'success');
      } catch {
        this.results.tests.push({ name: 'Dependencies Installed', status: 'warning' });
        this.log('node_modules not found - run npm install', 'warning');
      }

      this.results.tests.push({ 
        name: 'Package.json Validation', 
        status: 'passed',
        details: `${packageData.name} v${packageData.version}`
      });
      this.log(`Package validated: ${packageData.name} v${packageData.version}`, 'success');

      return true;
    } catch (error) {
      this.results.tests.push({ 
        name: 'Package.json Validation', 
        status: 'failed', 
        error: error.message 
      });
      this.log(`Package.json validation failed: ${error.message}`, 'error');
      return false;
    }
  }

  async testServerStartup() {
    this.log('Testing server startup capability...', 'info');
    
    return new Promise((resolve) => {
      let serverProcess;
      let startupTimeout;
      let healthCheckTimeout;
      
      const cleanup = () => {
        if (serverProcess && !serverProcess.killed) {
          serverProcess.kill();
        }
        if (startupTimeout) clearTimeout(startupTimeout);
        if (healthCheckTimeout) clearTimeout(healthCheckTimeout);
      };

      // Set timeout for startup
      startupTimeout = setTimeout(() => {
        cleanup();
        this.results.tests.push({ 
          name: 'Server Startup', 
          status: 'failed', 
          error: 'Server startup timeout (30s)' 
        });
        this.log('Server startup timeout after 30 seconds', 'error');
        resolve(false);
      }, 30000);

      try {
        // Start the server
        const isWindows = this.platform === 'win32';
        const command = isWindows ? 'npm.cmd' : 'npm';
        
        serverProcess = spawn(command, ['start'], {
          cwd: __dirname,
          stdio: ['ignore', 'pipe', 'pipe'],
          env: { ...process.env, NODE_ENV: 'test' }
        });

        let serverOutput = '';
        
        serverProcess.stdout.on('data', (data) => {
          serverOutput += data.toString();
          
          // Look for server ready indicators
          if (serverOutput.includes('Server running on') || 
              serverOutput.includes('listening on') ||
              serverOutput.includes('ready') ||
              serverOutput.includes('started')) {
            
            // Wait a moment then test connectivity
            healthCheckTimeout = setTimeout(async () => {
              try {
                const response = await this.testHttpConnection();
                cleanup();
                
                if (response) {
                  this.results.tests.push({ 
                    name: 'Server Startup', 
                    status: 'passed',
                    details: 'Server accessible on http://localhost:3001'
                  });
                  this.log('Server startup successful and accessible', 'success');
                  resolve(true);
                } else {
                  this.results.tests.push({ 
                    name: 'Server Startup', 
                    status: 'failed',
                    error: 'Server started but not accessible on port 3001'
                  });
                  this.log('Server started but not accessible', 'error');
                  resolve(false);
                }
              } catch (error) {
                cleanup();
                this.results.tests.push({ 
                  name: 'Server Startup', 
                  status: 'failed',
                  error: `Health check failed: ${error.message}`
                });
                this.log(`Server health check failed: ${error.message}`, 'error');
                resolve(false);
              }
            }, 3000);
          }
        });

        serverProcess.stderr.on('data', (data) => {
          const errorText = data.toString();
          if (errorText.includes('EADDRINUSE') || errorText.includes('address already in use')) {
            cleanup();
            this.results.tests.push({ 
              name: 'Server Startup', 
              status: 'warning',
              details: 'Port 3001 already in use - server may already be running'
            });
            this.log('Port 3001 already in use - server may already be running', 'warning');
            resolve(true); // Consider this a success since server is running
          }
        });

        serverProcess.on('error', (error) => {
          cleanup();
          this.results.tests.push({ 
            name: 'Server Startup', 
            status: 'failed',
            error: error.message
          });
          this.log(`Server startup error: ${error.message}`, 'error');
          resolve(false);
        });

        serverProcess.on('exit', (code, signal) => {
          if (code !== null && code !== 0) {
            cleanup();
            this.results.tests.push({ 
              name: 'Server Startup', 
              status: 'failed',
              error: `Server exited with code ${code}`
            });
            this.log(`Server exited with code ${code}`, 'error');
            resolve(false);
          }
        });

      } catch (error) {
        cleanup();
        this.results.tests.push({ 
          name: 'Server Startup', 
          status: 'failed',
          error: error.message
        });
        this.log(`Server startup failed: ${error.message}`, 'error');
        resolve(false);
      }
    });
  }

  async testHttpConnection() {
    return new Promise((resolve) => {
      const req = http.get('http://localhost:3001', { timeout: 5000 }, (res) => {
        resolve(res.statusCode >= 200 && res.statusCode < 400);
      });
      
      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });
    });
  }

  async testCLICommands() {
    this.log('Testing CLI command availability...', 'info');
    
    try {
      // Test basic CLI help
      const { stdout } = await execAsync('node cli/scorpion.js --help', { 
        cwd: __dirname,
        timeout: 10000 
      });
      
      if (stdout.includes('Scorpion') || stdout.includes('SCORPION')) {
        this.results.tests.push({ name: 'CLI Help', status: 'passed' });
        this.log('CLI help command working', 'success');
      } else {
        throw new Error('CLI help output does not contain expected content');
      }

      // Test CLI modules availability
      const modules = ['scan', 'recon', 'password', 'fim', 'threat-intel'];
      for (const module of modules) {
        try {
          const { stdout: moduleHelp } = await execAsync(`node cli/scorpion.js ${module} --help`, {
            cwd: __dirname,
            timeout: 5000
          });
          
          if (moduleHelp.includes('Usage:') || moduleHelp.includes('Options:')) {
            this.results.tests.push({ name: `CLI Module: ${module}`, status: 'passed' });
            this.log(`CLI module ${module} available`, 'success');
          } else {
            this.results.tests.push({ name: `CLI Module: ${module}`, status: 'warning' });
            this.log(`CLI module ${module} help incomplete`, 'warning');
          }
        } catch (error) {
          this.results.tests.push({ 
            name: `CLI Module: ${module}`, 
            status: 'failed',
            error: error.message
          });
          this.log(`CLI module ${module} failed: ${error.message}`, 'error');
        }
      }

      return true;
    } catch (error) {
      this.results.tests.push({ 
        name: 'CLI Commands', 
        status: 'failed',
        error: error.message
      });
      this.log(`CLI command test failed: ${error.message}`, 'error');
      return false;
    }
  }

  async runAllTests() {
    console.log('🦂 Scorpion Platform Startup Validation');
    console.log('=' .repeat(50));
    console.log(`Platform: ${this.platform} ${this.arch}`);
    console.log(`Node.js: ${this.nodeVersion}`);
    console.log('=' .repeat(50));

    const tests = [
      () => this.testSystemRequirements(),
      () => this.testPlatformScripts(),
      () => this.testPackageJson(),
      () => this.testCLICommands(),
      () => this.testServerStartup()
    ];

    let allPassed = true;

    for (const test of tests) {
      const result = await test();
      if (!result) allPassed = false;
      console.log(''); // Add spacing between tests
    }

    this.results.endTime = new Date().toISOString();
    this.results.success = allPassed;
    this.results.duration = new Date(this.results.endTime) - new Date(this.results.startTime);

    // Generate summary
    console.log('🏁 Validation Summary');
    console.log('=' .repeat(50));
    
    const passed = this.results.tests.filter(t => t.status === 'passed').length;
    const failed = this.results.tests.filter(t => t.status === 'failed').length;
    const warnings = this.results.tests.filter(t => t.status === 'warning').length;
    
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`⚠️  Warnings: ${warnings}`);
    console.log(`⏱️  Duration: ${Math.round(this.results.duration / 1000)}s`);
    
    if (allPassed) {
      this.log('🎉 All critical tests passed! Platform is ready for use.', 'success');
    } else {
      this.log('❌ Some tests failed. Please review the issues above.', 'error');
    }

    // Save detailed results
    const resultFile = path.join(__dirname, `startup-validation-${this.platform}.json`);
    await fs.writeFile(resultFile, JSON.stringify(this.results, null, 2));
    this.log(`Detailed results saved to: ${resultFile}`, 'info');

    return allPassed;
  }
}

// Run if called directly
const isMainModule = process.argv[1] && process.argv[1].endsWith('startup-test.js');
if (isMainModule) {
  try {
    const validator = new StartupValidator();
    const success = await validator.runAllTests();
    process.exit(success ? 0 : 1);
  } catch (error) {
    console.error('❌ Startup validation failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

export { StartupValidator };