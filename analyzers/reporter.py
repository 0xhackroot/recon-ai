import json
from pathlib import Path

def generate_latex_report(target: str, recon_data: dict, all_hits: list, llm_analysis: str) -> str:
    # Build table rows safely for LaTeX
    rows = ""
    for h in all_hits:
        url = h.get("url", "").replace("_", "\\_").replace("#", "\\#")
        status = h.get("status", "")
        size = h.get("length", "")
        words = h.get("words", "")
        ctype = h.get("content-type", "").replace("_", "\\_")
        rows += f"{url} & {status} & {size} & {words} & {ctype} \\\\\n\\hline\n"

    tech_hints = recon_data.get("tech_hints", "N/A").replace("_", "\\_").replace("&", "\\&")
    
    tex = f"""\\documentclass{{article}}
\\usepackage{{booktabs}}
\\usepackage{{hyperref}}
\\title{{Recon-AI Automated Fuzzing Report}}
\\author{{AI Agent}}
\\date{{\\today}}

\\begin{{document}}
\\maketitle

\\section{{Target Information}}
\\begin{{itemize}}
    \\item \\textbf{{URL:}} {target}
    \\item \\textbf{{Alive:}} {recon_data.get('is_alive', 'N/A')}}
    \\item \\textbf{{Server/Tech:}} {tech_hints}
\\end{{itemize}}

\\section{{Discovered Endpoints ({len(all_hits)} total)}}
\\begin{{table}}[h]
\\centering
\\resizebox{{\\textwidth}}{{!}}{{%
\\begin{{tabular}}{{llccc}}
\\toprule
URL & Status & Size (Bytes) & Words & Content-Type \\\\
\\midrule
{rows}
\\bottomrule
\\end{{tabular}}%
}}
\\end{{table}}

\\section{{AI Analysis \& Interpretation}}
{llm_analysis.replace('_', '\\_').replace('&', '\\&')}

\\end{{document}}
"""
    return tex
