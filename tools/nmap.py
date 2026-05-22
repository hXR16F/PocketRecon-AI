import subprocess
from typing import Optional, List, Dict


def run_nmap(
    target: str,
    ports: str,
    scan_type: str = "syn",
    os_detection: bool = True,
    service_detection: bool = True,
    script_scan: bool = False,
    scripts: Optional[List[str]] = None,
    script_args: Optional[str] = None,
    top_ports_count: Optional[int] = None,
    timing: int = 3,
    extra_args: Optional[List[str]] = None
) -> Dict:
    args = ["nmap"]

    args.append(f"-T{timing}")

    scan_map = {
        "syn": "-sS",
        "tcp": "-sT",
        "udp": "-sU",
        "aggressive": "-A",
    }

    if scan_type in scan_map:
        args.append(scan_map[scan_type])
    else:
        raise ValueError(f"Invalid scan_type: {scan_type}")

    if os_detection and scan_type != "aggressive":
        args.append("-O")

    if service_detection and scan_type != "aggressive":
        args.append("-sV")

    if ports:
        args.extend(["-p", ports])
    elif top_ports_count:
        args.extend(["--top-ports", str(top_ports_count)])

    if script_scan or scripts:
        if scripts:
            args.extend(["--script", ",".join(scripts)])
        else:
            args.append("--script=default")

        if script_args:
            args.extend(["--script-args", script_args])

    if extra_args:
        args.extend(extra_args)

    args.append(target)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=900
        )

        return {
            "target": target,
            "command": " ".join(args),
            "output": result.stdout if result.returncode == 0 else result.stderr,
            "return_code": result.returncode
        }

    except Exception as e:
        return {
            "target": target,
            "error": str(e),
            "command": " ".join(args)
        }
