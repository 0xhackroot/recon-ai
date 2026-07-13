# Ffuf Methodology Reference

| Command | Description |
|---------|-------------|
| `ffuf -w wordlist.txt:FUZZ -u http://target/FUZZ` | Directory Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://target/indexFUZZ` | Extension Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://target/blog/FUZZ.php` | Page Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://target/FUZZ -recursion -recursion-depth 1 -e .php -v` | Recursive Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u https://FUZZ.target.com/` | Sub-domain Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://target/ -H 'Host: FUZZ.target.com' -fs xxx` | VHost Fuzzing |
| `ffuf -w wordlist.txt:FUZZ -u http://target/admin.php?FUZZ=key -fs xxx` | Parameter Fuzzing - GET |
| `ffuf -w wordlist.txt:FUZZ -u http://target/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Parameter Fuzzing - POST |
| `ffuf -w ids.txt:FUZZ -u http://target/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx` | Value Fuzzing |

Use these as reference patterns, not fixed commands. Adapt to actual recon data and target behavior.
