#!/usr/bin/env python3
"""Simple Tkinter GUI for the Website Bug Scanner (its_over).

The GUI wraps the `scan_url` function from `its_over.py` and displays a
human‑readable summary of the scan.  It does not require any external GUI
libraries – Tkinter is part of the Python standard library.
"""

import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# Import the scanning logic from the existing module
from its_over import scan_url


def run_scan():
    url = url_var.get().strip()
    if not url:
        messagebox.showerror("Input error", "Please enter a URL.")
        return
    try:
        result = scan_url(url)
    except Exception as e:
        messagebox.showerror("Scan error", f"An error occurred: {e}")
        return

    if json_var.get():
        # Show raw JSON
        output = json.dumps(result, indent=2)
    else:
        if "error" in result:
            output = f"Error: {result['error']}"
        else:
            lines = []
            lines.append(f"URL: {result['url']}")
            lines.append(f"HTTP status : {result['http_status']}")
            lines.append(f"HTTPS       : {'yes' if result['https'] else 'no'}")
            lines.append(f"TLS valid   : {'yes' if result['tls_valid'] else 'no'}")
            lines.append("\nSecurity‑header check:")
            for hdr, ok in result["security_headers"].items():
                lines.append(f"  {hdr:27}: {'OK' if ok else 'MISSING'}")
            lines.append("\nHeuristics:")
            lines.append(f"  Suspicious keyword hits : {result['suspicious_keyword_hits']}")
            lines.append(f"  External script hits    : {result['external_script_hits']}")
            lines.append(f"  Overall risk score (0‑10): {result['overall_score']}")
            vt = result.get("virustotal")
            if vt:
                lines.append("\nVirusTotal summary:")
                lines.append(f"  Malicious : {vt['malicious']}")
                lines.append(f"  Suspicious: {vt['suspicious']}")
                lines.append(f"  Harmless  : {vt['harmless']}")
                lines.append(f"  Total scans: {vt['total']}")
            lines.append("\nInterpretation:")
            if result["overall_score"] >= 5:
                lines.append("  ⚠️  Red flags – investigate further.")
            else:
                lines.append("  ✅  No obvious issues detected.")
            output = "\n".join(lines)
    output_text.configure(state="normal")
    output_text.delete(1.0, tk.END)
    output_text.insert(tk.END, output)
    output_text.configure(state="disabled")

# -----------------------------------------------------------------------
# Build the GUI
# -----------------------------------------------------------------------
root = tk.Tk()
root.title("Website Bug Scanner")
root.geometry("800x600")

mainframe = ttk.Frame(root, padding="12")
mainframe.pack(fill=tk.BOTH, expand=True)

# URL entry
url_var = tk.StringVar()
url_label = ttk.Label(mainframe, text="Target URL:")
url_label.grid(row=0, column=0, sticky=tk.W, pady=5)
url_entry = ttk.Entry(mainframe, textvariable=url_var, width=70)
url_entry.grid(row=0, column=1, sticky=tk.W, pady=5)

# JSON toggle
json_var = tk.BooleanVar(value=False)
json_check = ttk.Checkbutton(mainframe, text="Show raw JSON", variable=json_var)
json_check.grid(row=1, column=1, sticky=tk.W, pady=5)

# Scan button
scan_btn = ttk.Button(mainframe, text="Run Scan", command=run_scan)
scan_btn.grid(row=2, column=1, sticky=tk.W, pady=5)

# Output area
output_text = scrolledtext.ScrolledText(mainframe, wrap=tk.WORD, height=25, state="disabled")
output_text.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=10)

# Make the grid stretch nicely
mainframe.columnconfigure(1, weight=1)
mainframe.rowconfigure(3, weight=1)

root.mainloop()
