#!/usr/bin/env python3
import sys
import os
from rich.console import Console

from config import WORDLIST_DIR, RESULTS_DIR, SCAN_TIMEOUT
from analyzers.groq import llm
from analyzers.prompts import get_prompt
from core.runner import recon, run_ffuf
from core.validator import get_ffuf_help_text, parse_llm_response, build_safe_command

console = Console()


def describe_wordlists(directory) -> list:
    """Returns filenames with line counts so the LLM can judge wordlist size/relevance."""
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


def main(target: str):
    if not target.startswith("http"):
        target = f"https://{target}"

    console.print(f"[bold blue][*] Target: {target}[/]")

    console.print("[*] Reading ffuf help...")
    ffuf_help_text = get_ffuf_help_text()

    console.print("[*] Loading wordlists...")
    wordlists = describe_wordlists(WORDLIST_DIR)

    console.print("[*] Running pre-fuzz recon...")
    recon_data = recon(target)
    console.print(
        f"    Alive: {recon_data['is_alive']} | "
        f"Size: {recon_data['baseline_size']} | "
        f"Soft404: {recon_data['soft_404_size']}"
    )
    console.print(f"    [dim]Probes: {recon_data.get('soft_404_probes')}[/]")

    if not recon_data["is_alive"]:
        console.print("[red][!] Target is dead. Exiting.[/]")
        return

    console.print("[*] Asking LLM for fuzzing parameters...")
    prompt = get_prompt(ffuf_help_text, wordlists, recon_data, SCAN_TIMEOUT)
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
            console.print("[dim]---RAW LLM OUTPUT (retry)---[/]")
            console.print(raw_llm_response)
            console.print("[dim]---END RAW OUTPUT---[/]")
            parsed = parse_llm_response(raw_llm_response)
        except ValueError as e2:
            console.print(f"[red][!] LLM failed twice. Aborting. ({e2})[/]")
            return

    console.print(f"    [cyan]LLM Reasoning: {parsed.get('reasoning', 'N/A')}[/]")
    console.print(f"    [dim]Fuzz mode: {parsed.get('fuzz_mode')}[/]")
    console.print(f"    [dim]LLM requested flags: {parsed.get('flags')}[/]")
    console.print(f"    [dim]LLM requested wordlist: {parsed.get('wordlist_filename')}[/]")

    try:
        safe_cmd, output_path = build_safe_command(
            parsed["flags"], parsed["wordlist_filename"], parsed["fuzz_mode"], target
        )
    except ValueError as e:
        console.print(f"[yellow][!] Invalid params from LLM ({e}). Retrying once...[/]")
        try:
            retry_prompt = f"Your previous choice failed: {e}. Choose valid values. " + prompt
            raw_llm_response = llm.generate(retry_prompt)
            console.print("[dim]---RAW LLM OUTPUT (param retry)---[/]")
            console.print(raw_llm_response)
            console.print("[dim]---END RAW OUTPUT---[/]")
            parsed = parse_llm_response(raw_llm_response)
            safe_cmd, output_path = build_safe_command(
                parsed["flags"], parsed["wordlist_filename"], parsed["fuzz_mode"], target
            )
        except ValueError as e2:
            console.print(f"[red][!] Failed twice building command. Aborting. ({e2})[/]")
            return

    console.print(f"    [dim]Final validated command: {' '.join(safe_cmd)}[/]")

    console.print("[bold green][*] Starting Fuzz...[/]")
    ffuf_results = run_ffuf(safe_cmd, output_path, timeout=SCAN_TIMEOUT)

    hits = ffuf_results.get("results", [])
    console.print(f"[bold green][+] Done! Found {len(hits)} endpoints.[/]")

    if hits:
        console.print_json(data=hits)
    else:
        console.print("[yellow]No hits found.[/]")
        if ffuf_results.get("error"):
            console.print(f"[red]ffuf stderr: {ffuf_results['error']}[/]")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python main.py <url>")
        sys.exit(1)
    main(sys.argv[1])