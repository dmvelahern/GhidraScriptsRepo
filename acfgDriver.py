"""
Usage: python3 acfgDriver.py

Purpose: Use Ghidra headless analyzer to traverse every function in a binary, 
extract the attributed CFG, and export to a JSON file

Notes:
Ghidra imports the binary every run with -import <binary>
If have already done analysis, then instead sub in (-process <filename.o>) (-noanalysis)
"""

import os
import subprocess

GHIDRA = r"C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC"
PROJECT = r"C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject"
PROJECT_NAME = "bcsd_initBinaries"
SCRIPT_PATH = os.path.join(GHIDRA, "GhidraScriptsRepo")
SCRIPT = "cfg.py"

# where to start reading files from to analyze
BUILD_ROOT = r"C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\build"
# folder to output the extacted ACFGs to
OUTPUT_DIR = r"C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\baseline_binaries_extracted_acfg"


headless = os.path.join(GHIDRA, "support", "analyzeHeadless.bat")

for root, _, files in os.walk(BUILD_ROOT):
    for filename in sorted(files):

        # if not filename.endswith(".o"):
        #     continue

        binary = os.path.join(root, filename)

        print("=" * 80)
        print("Processing:", binary)

        subprocess.run([
            headless,
            PROJECT,
            PROJECT_NAME,
            "-import", binary,
            "-scriptPath", SCRIPT_PATH,
            # give the OUTPUT_DIR as an arg to the cfg.py script
            "-postScript", SCRIPT, OUTPUT_DIR,
            "-autoAnalyze"
        ], check=True)