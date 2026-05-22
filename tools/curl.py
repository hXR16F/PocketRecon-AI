import subprocess


def curl_request(
    url: str,
    method: str = "GET",

    data=None,
    json_body: bool = False,

    headers: list[str] | None = None,
    query_params: dict | None = None,
    cookies: dict | None = None,

    follow_redirects: bool = False,
    timeout: int = 30,
    connect_timeout: int = 10,
    verbose: bool = False,

    extra_args: list[str] | None = None,
) -> dict:

    try:
        cmd = ["curl"]

        if verbose:
            cmd.append("-v")
        else:
            cmd.extend(["-sS"])

        cmd.extend(["-X", method.upper()])

        cmd.extend(["--max-time", str(timeout)])
        cmd.extend(["--connect-timeout", str(connect_timeout)])

        if follow_redirects:
            cmd.append("-L")

        if headers:
            for h in headers:
                cmd.extend(["-H", h])

        if cookies:
            cookie_str = "; ".join(
                f"{k}={v}" for k, v in cookies.items()
            )
            cmd.extend(["-b", cookie_str])

        elif json_body and data is not None:
            cmd.extend([
                "-H",
                "Content-Type: application/json"
            ])

            cmd.extend([
                "--data",
                json.dumps(data)
            ])

        elif data is not None:
            if isinstance(data, dict):
                for k, v in data.items():

                    if isinstance(v, list):
                        for item in v:
                            cmd.extend([
                                "--data-urlencode",
                                f"{k}={item}"
                            ])
                    else:
                        cmd.extend([
                            "--data-urlencode",
                            f"{k}={v}"
                        ])
            else:
                cmd.extend(["--data", str(data)])

        if query_params:
            query = "&".join([
                f"{k}={v}"
                for k, v in query_params.items()
            ])

            separator = "&" if "?" in url else "?"
            url += separator + query

        if extra_args:
            cmd.extend(extra_args)

        cmd.append(url)

        cmd.extend([
            "-w",
            "\n__STATUS__:%{http_code}"
        ])

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout + 5
        )

        stdout = result.stdout if result.returncode == 0 else ""
        stderr = result.stderr.strip()

        status_code = None

        if "__STATUS__:" in stdout:
            body, status = stdout.rsplit("__STATUS__:", 1)
            stdout = body.strip()
            status_code = status.strip()

        return {
            "success": result.returncode == 0,
            "url": url,
            "method": method.upper(),
            "status_code": status_code,
            "exit_code": result.returncode,
            "body": stdout,
            "stderr": stderr,
            "command": cmd if verbose else None
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "url": url,
            "method": method.upper(),
            "error": f"Request timed out after {timeout} seconds",
        }

    except Exception as e:
        return {
            "success": False,
            "url": url,
            "method": method.upper(),
            "error": str(e)
        }
