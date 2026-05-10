# ITS OVER – Web Security Scanner

A tiny, Python‑only helper that:

* fetches a URL,
* checks for common security‑header mis‑configurations,
* looks for suspicious JavaScript patterns,
* validates TLS/HTTPS,
* (optionally) queries VirusTotal for a quick malware verdict.

```bash
# Install dependencies
pip install -r requirements.txt

# Run a scan
python its_over.py https://example.com
```

Feel free to extend the keyword list, add deeper analyses, or hook this into CI pipelines.

*Created by Sagar Dhar – 2026*
