"""
Usage: python DRIVER_enhanceBbMetadata.py

Purpose:
Enhance every CFG JSON with Capstone-derived metadata.
"""

import os
import sys
import time
import subprocess

# Where to read the extracted CFG JSON files from
INPUT_DIR = r"C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\baseline_binaries_extracted_acfg"
# Where to put the enriched JSON files after processing
OUTPUT_DIR = r"C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\baseline_binaries_extracted_acfg_ENRICHED"
SCRIPT = os.path.join(os.path.dirname(__file__), "enhanceBbMetadata.py")

# Gather all files first
json_files = []

for root, _, files in os.walk(INPUT_DIR):
    for filename in sorted(files):
        if not filename.endswith(".json"):
            continue
        if filename.endswith("_ENRICHED.json"):
            continue

        json_files.append(os.path.join(root, filename))

total = len(json_files)

print(f"[+] Found {total} CFG JSON files.\n")


# Start processing each file
start_time = time.perf_counter()
for i, json_path in enumerate(json_files, start=1):

    print("=" * 80)
    print(f"[{i}/{total}] Processing:")
    print(json_path)

    subprocess.run(
        [
            sys.executable,
            SCRIPT,
            json_path,
            OUTPUT_DIR
        ],
        check=True
    )

    elapsed = time.perf_counter() - start_time
    avg_time = elapsed / i
    eta = avg_time * (total - i)

    print(
        f"[+] Completed {i}/{total} | "
        f"Elapsed: {elapsed:.1f}s | "
        f"ETA: {eta:.1f}s\n"
    )

# Print final summary
total_time = time.perf_counter() - start_time
print("=" * 80)
print(f"[+] Finished enriching {total} CFGs.")
print(f"[+] Total runtime: {total_time:.2f} seconds ({total_time/60:.2f} minutes)")