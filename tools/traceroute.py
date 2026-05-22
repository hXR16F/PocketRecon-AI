import platform
import subprocess


def trace_route(target: str) -> dict:
    cmd = ["tracert", target] if platform.system().lower() == "windows" else ["traceroute", target]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        return {
            "target": target,
            "output": result.stdout if result.returncode == 0 else result.stderr
        }

    except Exception as e:
        return {"target": target, "error": str(e)}
