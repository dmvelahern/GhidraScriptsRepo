#@category BinKit
#@runtime JYTHON

import os
import json
import re
from java.text import SimpleDateFormat
from java.util import Date
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

# --- CONFIGURATION ---
from ghidra.app.script import GhidraScript
args = getScriptArgs()
if len(args) >= 1:
    OUT_DIR = args[0]
else:
    OUT_DIR = os.path.join(os.getcwd(), "cfg_output")

# Or Hardcode a path for testing:
# OUT_DIR = "C:\\Users\\danie\\Desktop\\bcsd\\bcsd_GhidraProject\\GhidraScriptOutput\\test"


"""
## PURPOSE 
Use Ghidra headless ananlyzer to 
traverse every function in a binary, 
extract the attributed CFG,
and export to a JSON


EXAMPLE OUTPUT IS AT THE BOTTOM

## USAGE
IF NOT YET ANALYZED:

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -import "C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\build\clang\layers-clang-21_1_8-O0-x86_64.o" -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript cfg.py -autoAnalyze

-------------------------------------------------------------------------
IF ALREADY ANALYZED

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -process layers-clang-21_1_8-O0-x86_64.o -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript cfg.py -noanalysis
"""

def get_binary_metadata(program_name):
    """Extracts parsed filename groups and cryptographic metadata from the program."""
    info_options = currentProgram.getOptions("Program Information")
    binary_sha256 = info_options.getString("Executable SHA256", "Hash Not Computed")

    # Establish fallback defaults inside a metadata dict
    metadata = {
        "program_name": program_name,
        "binary_sha256": binary_sha256,
        "source_filename": "Unknown",
        "compiler": "Unknown",
        "compiler_version": "Unknown",
        "optimization_level": "Unknown",
        "arch": "Unknown"
    }

    filename_pattern = r"^(?P<source>[^-]+)-(?P<compiler>[^-]+)-(?P<compiler_version>[\d_]+)-(?P<opt>O[0-3s])-(?P<arch>[^.]+)\.o$"
    match = re.match(filename_pattern, program_name)
    
    if match:
        metadata["source_filename"] = match.group("source")
        metadata["compiler"] = match.group("compiler")
        metadata["compiler_version"] = match.group("compiler_version").replace("_", ".")
        metadata["optimization_level"] = match.group("opt")
        metadata["arch"] = match.group("arch")

    return metadata


def extract_node_bytes(block, listing):
    """Iterates through a basic block (convert from raw signed Java bytes into clean hex strings ex. 0xff )."""
    raw_bytes = []
    # Returns an iter of the instrs in this listing (in proper sequence), starting at the specified address
    ins_iter = listing.getInstructions(block, True)
    while ins_iter.hasNext():
        ins = ins_iter.next()
        java_bytes = ins.getBytes()
        hex_bytes = "".join([format(b & 0xff, '02x') for b in java_bytes])
        raw_bytes.append(hex_bytes)
    return raw_bytes


def process_function_cfg(func, block_model, listing, function_manager):
    """Processes a single function to generate its normalized node and edge maps."""
    # Ghidra API ops require a monitor to (report progress|cancel long tasks)
    ## Headless analyzer can use a dummy
    monitor = TaskMonitor.DUMMY
    func_body = func.getBody()

    cfg = {
        # All Function Metadata should be extracted during disassembly
        ## The Drs did not seem impressed by Ghidra decompilation artifacts, so only rely on Ghidra disassembly metadata for now
        "function_metadata": {
            # The binary's import tables (ie PLT) explicitly state if a jump points out of the file 
            ## into a library like glibc
            "is_thunk": func.isThunk(),
            "is_external_to_binary": func.isExternal(),
            # Ghidra tracks the stack pointer (RSP/ESP) as it reads the disassembly instructions. 
            ## If it sees sub rsp, 0x20 at the start of a function and add rsp, 0x20 at the end, it logs a 32-byte stack frame entirely from the disassembly layer
            "stack_frame_size_bytes": func.getStackFrame().getFrameSize(),
        },
        "nodes": {},
        "edges": []
    }
    
    # Track block entry points explicitly within this function to validate local edges
    local_block_addresses = set()
    addr_to_id = {}
    id_counter = 0

    # Loop 1: Extract Nodes (Basic Blocks) + Map addresses/Generate Sequential IDs
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    while code_blocks.hasNext():
        block = code_blocks.next()
        block_start = block.getMinAddress().toString()
        local_block_addresses.add(block_start)
        
        if block_start not in addr_to_id:
            addr_to_id[block_start] = str(id_counter)
            id_counter += 1
            
        local_id = addr_to_id[block_start]
        cfg["nodes"][local_id] = {
            "label": block.getName(),
            "raw_address": block_start,
            "raw_bytes": extract_node_bytes(block, listing)
        }

    # Loop 2: Extract Edges (Control Flow Connections) using Normalized Identifiers
    ## Re-instantiate the iterator to safely run through the blocks a second time
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    while code_blocks.hasNext():
        block = code_blocks.next()
        source_id = addr_to_id[block.getMinAddress().toString()]
        
        # ask Ghidra where block can branch to next (e.g., jump targets,
	    ## conditional branch paths, or sequential falls-through)
        destinations = block.getDestinations(monitor)
        while destinations.hasNext():
            reference = destinations.next()
            dest_addr = reference.getDestinationAddress()
            dest_str = dest_addr.toString()

            # Determine if this edge jumps out of the current function (e.g., calling an external API or another function ?within same binary?)
            is_local = dest_str in local_block_addresses
            
            # If the edge is local, use its normalized counterpart
            # If it's external (e.g. library call or func not same as current), keep the absolute target string or label it external + vaddr
            if is_local:
                if dest_str not in addr_to_id:
                    addr_to_id[dest_str] = str(id_counter)
                    id_counter += 1
                target_id = addr_to_id[dest_str]
            else:
                ext_func = function_manager.getFunctionAt(dest_addr)
                target_id = "EXT_" + (ext_func.getName() if ext_func else dest_str)

            cfg["edges"].append({
                "source": source_id,
                "target": target_id,
                "flow_type": reference.getFlowType().toString(),
                "is_local_to_function": is_local
            })

    return cfg


def main():
    # Setup Paths and Directories
    ## global var provided by Ghidra to currently loaded binary
    program_name = currentProgram.getName().replace(":", "_")
    # create output dir if doesnt already exist
    if not os.path.exists(OUT_DIR):
        os.makedirs(OUT_DIR)

    # create a semi-variable .json filename to ouput to
    out_path = os.path.join(OUT_DIR, "{}_acfg.json".format(program_name))

    print("\n--- STARTING CFG EXTRACTION ---")

    # Initialize Ghidra Sub-Systems
    ## Ghidra API object responsible for breaking a function down into basic blocks
    block_model = BasicBlockModel(currentProgram)
    listing = currentProgram.getListing()
    function_manager = currentProgram.getFunctionManager()
    # Fetches an iterator for all recognized functions in the binary, traversing forward through the code
    functions = function_manager.getFunctions(True)

    # Build base output structure
    output_json = {
        "binary_metadata": get_binary_metadata(program_name),
        "functions": {}
    }

    # Main iteration loop over ALL EXTRACTED FUNCTIONS IN THE BINARY
    for func in functions:
        func_name = func.getName()
        output_json["functions"][func_name] = process_function_cfg(
            func, block_model, listing, function_manager
        )

    # Save output dataset
    print("Writing CFG structural graph(s) to: " + out_path)
    with open(out_path, 'w') as f:
        json.dump(output_json, f, indent=4)

    print("--- EXTRACTION COMPLETE ---\n")


# Execution point trigger
if __name__ == "__main__":
    main()