import subprocess
import requests
import uuid
import json
from pathlib import Path
from config import RESULTS_DIR


def recon(target_url: str, timeout: int = 10) -> dict:
    """Pre-fuzz recon: check alive, grab baseline, probe soft-404 behavior across common extensions."""
    try:
        resp = requests.get(target_url, timeout=timeout, allow_redirects=True)
        baseline_status = resp.status_code
        baseline_size = len(resp.content)
        tech_hints = resp.headers.get("Server", "unknown")

        # probe multiple path styles — 404 behavior can differ by extension/framework routing
        probes = {}
        for suffix in ["", ".php", ".html", ".js"]:
            probe_path = f"{target_url.rstrip('/')}/{uuid.uuid4().hex}{suffix}"
            label = suffix.lstrip(".") or "no_extension"
            try:
                probe = requests.get(probe_path, timeout=timeout)
                probes[label] = {
                    "status": probe.status_code,
                    "size": len(probe.content)
                }
            except requests.RequestException:
                probes[label] = None

        # keep soft_404_size for backward compatibility, sourced from the no-extension probe
        no_ext = probes.get("no_extension")
        soft_404_size = no_ext["size"] if no_ext else None

        return {
            "target_url": target_url,
            "is_alive": True,
            "baseline_status": baseline_status,
            "baseline_size": baseline_size,
            "soft_404_size": soft_404_size,
            "soft_404_probes": probes,
            "tech_hints": tech_hints
        }
    except Exception as e:
        print(f"[RECON ERROR] {str(e)}")
        return {
            "target_url": target_url,
            "is_alive": False,
            "baseline_status": None,
            "baseline_size": None,
            "soft_404_size": None,
            "soft_404_probes": {},
            "tech_hints": f"Error: {str(e)}"
        }


def run_ffuf(command: list, output_path: str, timeout: int = 120):
    """Executes the safe command."""
    RESULTS_DIR.mkdir(exist_ok=True)
    print(f"\n[EXECUTING] {' '.join(command)}\n")

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"results": [], "error": f"ffuf timed out after {timeout}s"}

    out_file = Path(output_path)
    if out_file.exists():
        with open(out_file) as f:
            return json.load(f)
    return {"results": [], "error": result.stderr}