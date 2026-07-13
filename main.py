#!/usr/bin/env python3
import sys
import os
from rich.console import Console

from config import WORDLIST_DIR, RESULTS_DIR, SCAN_TIMEOUT, MAX_RECURSION_DEPTH, MAX_RECURSE_TARGETS
from analyzers.groq import llm
from analyzers.prompts import get_prompt, get_recurse_prompt, RECURSE_SCHEMA
from core.runner import recon, run_ffuf
from core.validator import (
    get_ffuf_help_text, parse_llm_response, build_safe_command, extract_directory_candidates
)

console = Console()


def describe_wordlists(directory) -> list:
    described = []
    for f in os.listdir(directory):
        if f.startswith('.'):
            continue
        path = os.path.join(directory, f)
        if not os.path.isfile(path):
            continue
        try:
            with open(path, 'r', errors='ignore') as fh:
                line_count = sum(1 for _ in fh)
            described.append(f"{f} ({line_count} lines)")
        except Exception:
            described.append(f"{f} (unreadable)")
    return described


def load_methodology() -> str:
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "knowledge", "ffuf_methodology.md")
    try:
        with open(path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        console.print("[dim]    (no methodology file found, skipping)[/]")
        return ""


def scan_target(target: str, ffuf_help_text: str, wordlists: list, methodology: str) -> list:
    console.print(f"[*] Running pre-fuzz recon on {target}...")
    recon_data = recon(target)
    console.print(
        f"    Alive: {recon_data['is_alive']} | "
        f"Size: {recon_data['baseline_size']} | "
        f"Soft404: {recon_data['soft_404_size']}"
    )

    if not recon_data["is_alive"]:
        console.print(f"[red][!] {target} is dead. Skipping.[/]")
        return []

    prompt = get_prompt(ffuf_help_text, wordlists, recon_data, SCAN_TIMEOUT, methodology)
    raw_llm_response = llm.generate(prompt)

    console.print("[dim]---RAW LLM OUTPUT---[/]")
    console.print(raw_llm_response)
    console.print("[dim]---END RAW OUTPUT---[/]")

    try:
        parsed = parse_llm_response(raw_llm_response)
    except ValueError as e:
        console.print(f"[yellow][!] LLM failed first try ({e}). Retrying once...[/]")
        try:
            raw_llm_response = llm.generate(
                "You failed to output valid JSON last time. Try again. " + prompt
            )
            parsed = parse_llm_response(raw_llm_response)
        except ValueError as e2:
            console.print(f"[red][!] LLM failed twice. Skipping {target}. ({e2})[/]")
            return []

    console.print(f"    [cyan]LLM Reasoning: {parsed.get('reasoning', 'N/A')}[/]")
    console.print(f"    [dim]Fuzz mode: {parsed.get('fuzz_mode')} | Flags: {parsed.get('flags')} | Wordlist: {parsed.get('wordlist_filename')}[/]")

    try:
        safe_cmd, output_path = build_safe_command(
            parsed["flags"], parsed["wordlist_filename"], parsed["fuzz_mode"], target
        )
    except ValueError as e:
        console.print(f"[yellow][!] Invalid params ({e}). Retrying once...[/]")
        try:
            retry_prompt = f"Your previous choice failed: {e}. Choose valid values. " + prompt
            raw_llm_response = llm.generate(retry_prompt)
            parsed = parse_llm_response(raw_llm_response)
            safe_cmd, output_path = build_safe_command(
                parsed["flags"], parsed["wordlist_filename"], parsed["fuzz_mode"], target
            )
        except ValueError as e2:
            console.print(f"[red][!] Failed twice building command. Skipping {target}. ({e2})[/]")
            return []

    console.print(f"    [dim]Final validated command: {' '.join(safe_cmd)}[/]")
    console.print(f"[bold green][*] Fuzzing {target}...[/]")
    ffuf_results = run_ffuf(safe_cmd, output_path, timeout=SCAN_TIMEOUT)
    hits = ffuf_results.get("results", [])
    console.print(f"[bold green][+] {target}: found {len(hits)} endpoints.[/]")

    if not hits and ffuf_results.get("error"):
        console.print(f"[red]ffuf stderr: {ffuf_results['error']}[/]")

    return hits


def recursive_fuzz(target: str, ffuf_help_text: str, wordlists: list, methodology: str, depth: int, all_hits: list):
    hits = scan_target(target, ffuf_help_text, wordlists, methodology)
    all_hits.extend(hits)

    if depth >= MAX_RECURSION_DEPTH:
        console.print("[dim]    Max recursion depth reached, not going deeper.[/]")
        return

    candidates = extract_directory_candidates(hits)
    if not candidates:
        console.print("[dim]    No directory candidates found — nothing to recurse into.[/]")
        return

    console.print(f"[*] Found {len(candidates)} directory candidate(s) at depth {depth}: {candidates}")
    console.print("[*] Asking LLM if any are worth exploring...")
    recurse_prompt = get_recurse_prompt(candidates, depth, MAX_RECURSION_DEPTH, MAX_RECURSE_TARGETS)
    raw = llm.generate(recurse_prompt)

    try:
        decision = parse_llm_response(raw, schema=RECURSE_SCHEMA)
    except ValueError as e:
        console.print(f"[yellow][!] Recursion decision failed to parse ({e}). Stopping recursion here.[/]")
        return

    console.print(f"    [cyan]Recursion reasoning: {decision.get('reasoning', 'N/A')}[/]")

    if not decision.get("recurse") or not decision.get("targets"):
        console.print("[dim]    LLM chose not to recurse further.[/]")
        return

    targets = decision["targets"][:MAX_RECURSE_TARGETS]
    for sub_target in targets:
        if sub_target not in candidates:
            console.print(f"[yellow][!] LLM chose an invalid target ({sub_target}), skipping.[/]")
            continue
        console.print(f"[bold blue][*] Recursing into {sub_target} (depth {depth + 1})...[/]")
        recursive_fuzz(sub_target, ffuf_help_text, wordlists, methodology, depth + 1, all_hits)


def main(target: str):
    if not target.startswith("http"):
        target = f"https://{target}"

    console.print(f"[bold blue][*] Target: {target}[/]")

    console.print("[*] Reading ffuf help...")
    ffuf_help_text = get_ffuf_help_text()

    console.print("[*] Loading methodology reference...")
    methodology = load_methodology()

    console.print("[*] Loading wordlists...")
    wordlists = describe_wordlists(WORDLIST_DIR)

    all_hits = []
    recursive_fuzz(target, ffuf_help_text, wordlists, methodology, depth=0, all_hits=all_hits)

    console.print(f"\n[bold green][+] Total across all scans: {len(all_hits)} endpoints found.[/]")
    if all_hits:
        console.print_json(data=all_hits)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <url>")
        sys.exit(1)
    main(sys.argv[1])