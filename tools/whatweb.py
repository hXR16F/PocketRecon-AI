import subprocess


def run_whatweb(target: str) -> dict:
    args = ["whatweb", target]

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=20,
            stdin=subprocess.DEVNULL,
        )

        stdout = result.stdout.strip()
        stderr = result.stderr.strip()

        output = stdout
        if stderr:
            output += "\n" + stderr

        if len(output) > 12000:
            output = output[:12000] + "\n\n[TRUNCATED]"

        return {
            "target": target,
            "tool": "whatweb",
            "output": output,
            "return_code": result.returncode,
        }

    except subprocess.TimeoutExpired:
        return {
            "target": target,
            "error": "whatweb timed out",
        }

    except FileNotFoundError:
        return {
            "target": target,
            "error": "whatweb not installed or not in PATH",
        }

    except Exception as e:
        return {
            "target": target,
            "error": str(e),
        }
