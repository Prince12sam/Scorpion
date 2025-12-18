"""
Remote Access Module - SSH Remote Log Access
Enables Scorpion to analyze logs on remote servers without manual copying
"""
import asyncio
import subprocess
import tempfile
from typing import List, Optional, Dict, Any
from pathlib import Path
from dataclasses import dataclass
import os


@dataclass
class RemoteServer:
    """Remote server configuration"""
    host: str
    user: str
    port: int = 22
    ssh_key: Optional[str] = None
    log_path: str = "/var/log/"


class SSHRemoteAccess:
    """SSH-based remote log access for distributed threat hunting"""
    
    def __init__(self, ssh_key: Optional[str] = None):
        self.ssh_key = ssh_key or os.path.expanduser("~/.ssh/id_rsa")
        self.temp_dir = None
        
    def parse_ssh_url(self, ssh_url: str) -> RemoteServer:
        """
        Parse SSH URL into RemoteServer object
        
        Formats:
        - ssh://user@host:/path/to/logs
        - user@host:/path/to/logs
        - ssh://user@host:port:/path/to/logs
        
        Returns:
            RemoteServer object
        """
        # Remove ssh:// prefix if present
        url = ssh_url.replace("ssh://", "")
        
        # Split into user@host:port:/path
        if "@" not in url:
            raise ValueError("SSH URL must contain user@host format")
        
        # Extract user and rest
        user, rest = url.split("@", 1)
        
        # Extract host, port (optional), and path
        if ":" not in rest:
            raise ValueError("SSH URL must contain path (user@host:/path)")
        
        # Check if port is specified (host:port:/path vs host:/path)
        parts = rest.split(":")
        if len(parts) == 2:
            # host:/path
            host, log_path = parts
            port = 22
        elif len(parts) == 3:
            # host:port:/path
            host, port_str, log_path = parts
            port = int(port_str)
        else:
            raise ValueError("Invalid SSH URL format")
        
        return RemoteServer(
            host=host,
            user=user,
            port=port,
            log_path=log_path,
            ssh_key=self.ssh_key
        )
    
    def _build_ssh_command(self, server: RemoteServer, remote_command: str) -> List[str]:
        """Build SSH command with proper options"""
        cmd = [
            "ssh",
            "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "LogLevel=ERROR",
            "-p", str(server.port),
        ]
        
        # Add SSH key if specified
        if server.ssh_key and os.path.exists(server.ssh_key):
            cmd.extend(["-i", server.ssh_key])
        
        # Add user@host
        cmd.append(f"{server.user}@{server.host}")
        
        # Add remote command
        cmd.append(remote_command)
        
        return cmd
    
    async def fetch_remote_logs(self, server: RemoteServer, output_path: str) -> bool:
        """
        Fetch logs from remote server via SCP
        
        Args:
            server: Remote server configuration
            output_path: Local path to save logs
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Build SCP command
            scp_cmd = [
                "scp",
                "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "LogLevel=ERROR",
                "-P", str(server.port),
            ]
            
            # Add SSH key if specified
            if server.ssh_key and os.path.exists(server.ssh_key):
                scp_cmd.extend(["-i", server.ssh_key])
            
            # Add source and destination
            # Check if log_path is a file or directory
            remote_path = f"{server.user}@{server.host}:{server.log_path}"
            
            # If directory, use recursive
            if not server.log_path.endswith(('.log', '.txt')):
                scp_cmd.append("-r")
            
            scp_cmd.extend([remote_path, output_path])
            
            # Execute SCP
            process = await asyncio.create_subprocess_exec(
                *scp_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                return True
            else:
                print(f"SCP failed: {stderr.decode('utf-8', errors='ignore')}")
                return False
                
        except Exception as e:
            print(f"Error fetching remote logs: {e}")
            return False
    
    async def read_remote_file(self, server: RemoteServer, max_lines: int = 10000) -> List[str]:
        """
        Read remote log file via SSH (streaming)
        
        Args:
            server: Remote server configuration
            max_lines: Maximum lines to read
            
        Returns:
            List of log lines
        """
        try:
            # Build command to tail log file
            remote_cmd = f"tail -n {max_lines} {server.log_path} 2>/dev/null || cat {server.log_path} 2>/dev/null | head -n {max_lines}"
            
            ssh_cmd = self._build_ssh_command(server, remote_cmd)
            
            # Execute SSH
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                lines = stdout.decode('utf-8', errors='ignore').splitlines()
                return lines
            else:
                print(f"SSH read failed: {stderr.decode('utf-8', errors='ignore')}")
                return []
                
        except Exception as e:
            print(f"Error reading remote file: {e}")
            return []
    
    async def check_connectivity(self, server: RemoteServer) -> bool:
        """
        Test SSH connectivity to remote server
        
        Args:
            server: Remote server configuration
            
        Returns:
            True if connection successful, False otherwise
        """
        try:
            ssh_cmd = self._build_ssh_command(server, "echo 'OK'")
            
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return process.returncode == 0 and b"OK" in stdout
            
        except Exception as e:
            print(f"Connectivity check failed: {e}")
            return False
    
    async def list_remote_logs(self, server: RemoteServer) -> List[str]:
        """
        List available log files on remote server
        
        Args:
            server: Remote server configuration
            
        Returns:
            List of log file paths
        """
        try:
            remote_cmd = f"find {server.log_path} -type f -name '*.log' 2>/dev/null | head -n 50"
            
            ssh_cmd = self._build_ssh_command(server, remote_cmd)
            
            process = await asyncio.create_subprocess_exec(
                *ssh_cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                log_files = stdout.decode('utf-8', errors='ignore').splitlines()
                return [f for f in log_files if f.strip()]
            else:
                return []
                
        except Exception as e:
            print(f"Error listing remote logs: {e}")
            return []
    
    async def fetch_from_multiple_servers(
        self, 
        servers: List[RemoteServer], 
        output_dir: str
    ) -> Dict[str, bool]:
        """
        Fetch logs from multiple servers in parallel
        
        Args:
            servers: List of remote servers
            output_dir: Local directory to save logs
            
        Returns:
            Dict mapping server host to success status
        """
        # Create output directory
        os.makedirs(output_dir, exist_ok=True)
        
        # Create tasks for parallel fetching
        tasks = []
        for server in servers:
            server_output = os.path.join(output_dir, f"{server.host}_logs")
            task = self.fetch_remote_logs(server, server_output)
            tasks.append((server.host, task))
        
        # Execute in parallel
        results = {}
        for host, task in tasks:
            success = await task
            results[host] = success
        
        return results
    
    def parse_server_list(self, server_file: str) -> List[RemoteServer]:
        """
        Parse server list from file
        
        File format (one per line):
        user@host:/path/to/logs
        user@host:port:/path/to/logs
        ssh://user@host:/path/to/logs
        
        Args:
            server_file: Path to server list file
            
        Returns:
            List of RemoteServer objects
        """
        servers = []
        
        try:
            with open(server_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    
                    # Skip empty lines and comments
                    if not line or line.startswith('#'):
                        continue
                    
                    try:
                        server = self.parse_ssh_url(line)
                        servers.append(server)
                    except ValueError as e:
                        print(f"Invalid server line '{line}': {e}")
                        continue
        except FileNotFoundError:
            print(f"Server list file not found: {server_file}")
        
        return servers


# Convenience functions
def is_ssh_url(path: str) -> bool:
    """Check if path is SSH URL"""
    return path.startswith("ssh://") or ("@" in path and ":" in path)


async def fetch_remote_log(ssh_url: str, ssh_key: Optional[str] = None) -> List[str]:
    """
    Fetch log from remote server
    
    Args:
        ssh_url: SSH URL (ssh://user@host:/path or user@host:/path)
        ssh_key: Path to SSH private key
        
    Returns:
        List of log lines
    """
    accessor = SSHRemoteAccess(ssh_key=ssh_key)
    server = accessor.parse_ssh_url(ssh_url)
    
    # Check connectivity first
    if not await accessor.check_connectivity(server):
        print(f"Cannot connect to {server.host}")
        return []
    
    # Read remote file
    return await accessor.read_remote_file(server)


async def fetch_multiple_servers(
    server_file: str, 
    output_dir: str,
    ssh_key: Optional[str] = None
) -> Dict[str, bool]:
    """
    Fetch logs from multiple servers
    
    Args:
        server_file: File containing server list
        output_dir: Output directory for logs
        ssh_key: Path to SSH private key
        
    Returns:
        Dict mapping server to success status
    """
    accessor = SSHRemoteAccess(ssh_key=ssh_key)
    servers = accessor.parse_server_list(server_file)
    
    if not servers:
        print("No valid servers found in server list")
        return {}
    
    return await accessor.fetch_from_multiple_servers(servers, output_dir)


# Example usage
if __name__ == "__main__":
    import sys
    
    async def test():
        # Test single server
        accessor = SSHRemoteAccess()
        
        # Parse URL
        server = accessor.parse_ssh_url("user@192.168.1.100:/var/log/auth.log")
        print(f"Parsed: {server}")
        
        # Test connectivity
        connected = await accessor.check_connectivity(server)
        print(f"Connected: {connected}")
        
        if connected:
            # List logs
            logs = await accessor.list_remote_logs(server)
            print(f"Found {len(logs)} log files")
            
            # Read log
            lines = await accessor.read_remote_file(server)
            print(f"Read {len(lines)} lines")
    
    asyncio.run(test())
