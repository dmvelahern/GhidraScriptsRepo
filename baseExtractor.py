#@category BinKit
#@runtime JYTHON


"""
PURPOSE: Extract the assembly instructions from one binary using Ghidra Headless mode

USAGE: Run from this dir with either of the following commands
C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\support>

IF NOT ALREADY ANALYZED

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -import "C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\build\clang\bit_ops-clang-21_1_8-O0.o" -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript [THIS_FILE].py -autoAnalyze

-------------------------------------------------------------------------
IF ALREADY ANALYZED

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -process bit_ops-clang-21_1_8-O0.o -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript [THIS_FILE].py -autoAnalyze


"""