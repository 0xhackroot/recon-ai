import json

SYSTEM_PROMPT = """You are a fuzzing parameter advisor. You generate ffuf command arguments based on recon data. You do NOT choose the target or output path — those are fixed by the system based on your fuzz_mode choice.

## ffuf help output (use this to understand what each flag does and pick correctly)
{ffuf_help_text}

## Available wordlists (choose EXACTLY one filename from this list — write ONLY the filename in your answer, not the "(N lines)" part, that's just size info to help you judge relevance)
{wordlist_filenames}

## Recon data
- URL: {target_url}
- Alive: {is_alive}
- Baseline status: {baseline_status}
- Baseline size (bytes): {baseline_size}
- Tech hints: {tech_hints}

## Soft-404 probe results (random nonexistent paths tested with different extensions)
{soft_404_probes}

Each probe shows the status code and size the server returned for a path that does NOT exist.
If a probe's status is 200 (not 404), that extension style triggers a SOFT-404 — filter by size for that case.
If a probe's status is a real 404, status-code filtering will work reliably for that path style.

Also watch for generic error pages: if you know (from prior scans on this target) that certain status codes like 403 or 500 return an identical, fixed-size error body regardless of the path requested, filter those out too (by status code, size, or both) — they are not real findings.

## Fuzzing modes (choose ONE)
- "path": fuzzes directories/files under the target, e.g. target.com/FUZZ (admin, login, api, etc).
- "subdomain": fuzzes subdomains of the target, e.g. FUZZ.target.com. Only sensible on a bare root domain.

Pick whichever mode makes more sense. If unsure, "path" is the safer default.

## Time constraint
This scan MUST complete within {scan_timeout} seconds or it will be killed with zero results.
Wordlists over 10,000 lines need -t 80-150. Under 5,000 lines, -t 40-60 is fine.

## Task
Analyze the recon data and soft-404 probes above, then pick fuzzing parameters.

Filtering priority:
1. Prefer status-code filtering (-fc) when probes show real 404s — reliable across path styles even if body sizes differ.
2. Use size-based filtering (-fs) only where probes show a soft-404 (status 200 for a missing path).
3. Never use "-mc all" as your only filter alongside a single -fs value — combine status and size filtering if the target needs both, or be specific with -mc codes.

Choose a wordlist appropriate to your fuzz_mode. Prefer larger, general wordlists (hundreds+ lines) unless a small specialized list is clearly better. Avoid near-empty wordlists (under ~30 lines).

Respond with ONLY a JSON object in EXACTLY this format (FORMAT example only — every value is a placeholder, not a real answer):

{{
  "fuzz_mode": "<path or subdomain>",
  "flags": ["<flag1>", "<value1>", "<flag2>", "<value2>"],
  "wordlist_filename": "<pick one exact filename from the list above>",
  "reasoning": "<explain your specific choices using the actual recon numbers and probe results above>"
}}

Do not output a JSON schema. Do not include "type", "properties", or "required" keys.
Do not copy the placeholder text literally — every value must come from your own analysis."""

FFUF_ARGS_SCHEMA = {
    "type": "object",
    "properties": {
        "fuzz_mode": {"type": "string", "enum": ["path", "subdomain"]},
        "flags": {"type": "array", "items": {"type": "string"}},
        "wordlist_filename": {"type": "string"},
        "reasoning": {"type": "string"}
    },
    "required": ["fuzz_mode", "flags", "wordlist_filename", "reasoning"],
    "additionalProperties": False
}


RECURSE_SYSTEM_PROMPT = """You just completed a fuzzing scan and found some directories (paths that returned a 301 redirect to a trailing-slash version of themselves).

## Discovered directories
{directories}

## Current recursion depth: {depth} (max allowed: {max_depth})
## Max directories you may choose to recurse into: {max_targets}

## Task
Decide whether any of these directories are worth fuzzing further (to discover files/subdirectories inside them). Prioritize directories that look interesting for security discovery (e.g. admin panels, content management directories, config-adjacent names) over generic static-asset directories (e.g. images, css, fonts) unless you have a specific reason to explore them.

Respond with ONLY a JSON object in EXACTLY this format (FORMAT example only, not real values):

{{
  "recurse": true,
  "targets": ["<directory_url_1>", "<directory_url_2>"],
  "reasoning": "<why these directories and not others, or why none are worth it>"
}}

If none are worth exploring further, return "recurse": false and an empty "targets" list.
Do not select more than {max_targets} targets. Do not copy the placeholder literally."""

RECURSE_SCHEMA = {
    "type": "object",
    "properties": {
        "recurse": {"type": "boolean"},
        "targets": {"type": "array", "items": {"type": "string"}},
        "reasoning": {"type": "string"}
    },
    "required": ["recurse", "targets", "reasoning"],
    "additionalProperties": False
}


# in prompts.py
def get_prompt(ffuf_help_text: str, wordlists: list, recon_data: dict, scan_timeout: int, methodology: str = "") -> str:
    probes = recon_data.get("soft_404_probes", {})
    probes_text = json.dumps(probes, indent=2)
    recon_fields = {k: v for k, v in recon_data.items() if k != "soft_404_probes"}

    return SYSTEM_PROMPT.format(
        ffuf_help_text=ffuf_help_text,
        methodology=methodology,
        wordlist_filenames="\n".join(wordlists),
        soft_404_probes=probes_text,
        scan_timeout=scan_timeout,
        **recon_fields
    )

def get_recurse_prompt(directories: list, depth: int, max_depth: int, max_targets: int) -> str:
    dirs_text = "\n".join(directories) if directories else "(none found)"
    return RECURSE_SYSTEM_PROMPT.format(
        directories=dirs_text,
        depth=depth,
        max_depth=max_depth,
        max_targets=max_targets
    )