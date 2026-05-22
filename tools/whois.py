import json


def whois_lookup(domain: str) -> dict:
    try:
        import whois

        w = whois.whois(domain)

        output_dict = {}

        for attr in dir(w):
            if not attr.startswith("_") and callable(getattr(w, attr)) is False:
                value = getattr(w, attr)
                if isinstance(value, str):
                    output_dict[attr] = value
                elif isinstance(value, list):
                    output_dict[f"{attr}_list"] = [str(v) for v in value]
                else:
                    output_dict[attr] = str(value)

        output_dict["text"] = w.text if w.text else ""

        return {
            "domain": domain,
            "output": json.dumps(output_dict, indent=2, default=str),
            "raw_text": w.text if w.text else ""
        }

    except Exception as e:
        return {"error": str(e), "domain": domain}
