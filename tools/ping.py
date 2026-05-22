import platform
import subprocess


def ping_target(target: str, count: int = 1) -> dict:
    param = "-n" if platform.system().lower() == "windows" else "-c"

    try:
        result = subprocess.run(
            ["ping", param, str(count), target],
            capture_output=True,
            text=True,
            timeout=15
        )

        output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"
        return {"target": target, "count": count, "output": output}
    except Exception as e:
        return {"error": str(e), "target": target}
