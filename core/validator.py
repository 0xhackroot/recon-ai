import subprocess
import json
import os
import uuid
import re
from urllib.parse import urlparse
from jsonschema import validate, ValidationError
from config import WORDLIST_DIR, RESULTS_DIR
from analyzers.prompts import FFUF_ARGS_SCHEMA


def get_ffuf_help_text() -> str:
    """Raw ffuf -h output, given to the LLM directly so it can read flag descriptions itself."""
    result = subprocess.run(["ffuf", "-h"], capture_output=True, text=True)
    return result.stdout


def get_valid_ffuf_flags() -> list:
    """Flag names only, used for validation."""
    result = subprocess.run(["ffuf", "-h"], capture_output=True, text=True)
    flags = set(re.findall(r'(-{1,2}[a-zA-Z\-]+)', result.stdout))
    return list(flags)


def parse_llm_response(raw_text: str) -> dict:
    """Extracts the first complete JSON object from the LLM output."""
    cleaned = raw_text.strip()

    start = cleaned.find('{')
    if start == -1:
        raise ValueError("LLM output invalid: no JSON object found")

    depth = 0
    end = None
    for i in range(start, len(cleaned)):
        if cleaned[i] == '{':
            depth += 1
        elif cleaned[i] == '}':
            depth -= 1
            if depth == 0:
                end = i + 1
                break

    if end is None:
        raise ValueError("LLM output invalid: unterminated JSON object")

    json_str = cleaned[start:end]

    try:
        data = json.loads(json_str)
        validate(instance=data, schema=FFUF_ARGS_SCHEMA)
        return data
    except (json.JSONDecodeError, ValidationError) as e:
        raise ValueError(f"LLM output invalid: {e}")


def strip_flag(args: list, flag: str) -> list:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a == flag:
            skip = True
            continue
        out.append(a)
    return out


def resolve_wordlist(llm_filename: str) -> str:
    if os.path.sep in llm_filename or ".." in llm_filename or "/" in llm_filename:
        raise ValueError("Invalid wordlist name")
    candidate = os.path.abspath(os.path.join(WORDLIST_DIR, llm_filename))
    if not candidate.startswith(str(WORDLIST_DIR) + os.sep):
        raise ValueError("Wordlist escapes allowed directory")
    if not os.path.isfile(candidate):
        raise ValueError(f"Wordlist does not exist: {llm_filename}")
    return candidate


def build_locked_url(target: str, fuzz_mode: str) -> str:
    """
    Builds the locked, safe URL for the given fuzz mode.
    Code owns WHERE FUZZ can legally go — LLM only chose the mode.
    """
    parsed = urlparse(target)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path

    if fuzz_mode == "subdomain":
        return f"{scheme}://FUZZ.{netloc}"
    else:
        base = target.rstrip("/")
        return f"{base}/FUZZ"


def build_safe_command(llm_flags: list, llm_wordlist: str, fuzz_mode: str, locked_target: str):
    valid_flags = get_valid_ffuf_flags()

    args = []
    i = 0
    while i < len(llm_flags):
        arg = llm_flags[i]
        if arg.startswith("-") and arg in valid_flags:
            args.append(arg)
            if i + 1 < len(llm_flags) and not llm_flags[i + 1].startswith("-"):
                args.append(llm_flags[i + 1])
                i += 1
        i += 1

    args = strip_flag(args, "-u")
    args = strip_flag(args, "-o")
    args = strip_flag(args, "-of")
    args = strip_flag(args, "-w")

    if fuzz_mode not in ("path", "subdomain"):
        fuzz_mode = "path"

    safe_url = build_locked_url(locked_target, fuzz_mode)
    args += ["-u", safe_url]

    output_path = str(RESULTS_DIR / f"{uuid.uuid4().hex}.json")
    args += ["-o", output_path, "-of", "json"]

    wordlist_path = resolve_wordlist(llm_wordlist)
    args += ["-w", wordlist_path]

    return ["ffuf"] + args, output_path