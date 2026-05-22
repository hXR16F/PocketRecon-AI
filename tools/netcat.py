import platform
import subprocess
from typing import Optional


def netcat_connect(
    target: str,
    port: int,
    data: Optional[str] = None
) -> dict:
    os_name = platform.system()

    if "Windows" in os_name or "nt" in os_name.lower():
        binary = "ncat"
    else:
        binary = "nc"

    if data:
        cmd = [binary, "-nv", target, str(port)]
    else:
        cmd = [binary, "-zv", target, str(port)]

    try:
        result = subprocess.run(
            cmd,
            input=data,
            capture_output=True,
            text=True,
            timeout=10
        )

        connected = result.returncode == 0

        return {
            "target": target,
            "port": port,
            "status": "connected" if connected else "disconnected",
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip(),
            "returncode": result.returncode,
            "command": " ".join(cmd),
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "port": port,
            "status": "timeout",
            "error": "Connection timed out",
        }

    except FileNotFoundError:
        return {
            "target": target,
            "port": port,
            "status": "error",
            "error": f"{binary} not found in PATH",
        }

    except Exception as e:
        return {
            "target": target,
            "port": port,
            "status": "error",
            "error": str(e),
        }
