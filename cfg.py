#@category BinKit
#@runtime JYTHON

OUT_DIR = "C:\\Users\\danie\\Desktop\\bcsd\\bcsd_GhidraProject\\GhidraScriptOutput\\test"


"""
## PURPOSE 
Use Ghidra headless ananlyzer to 
traverse every function in a binary, 
extract the CFG,
and export to a JSON


EXAMPLE OUTPUT IS AT THE BOTTOM

## USAGE
IF NOT YET ANALYZED:

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -import "C:\Users\danie\VirtualBox VMs\VirtualBoxShares\UbuntuShare\build\clang\layers-clang-21_1_8-O0.o" -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript cfg.py -autoAnalyze

-------------------------------------------------------------------------
IF ALREADY ANALYZED

analyzeHeadless "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject" bcsd_initBinaries -process layers-clang-21_1_8-O0.o -scriptPath "C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\ghidra_12.0.4_PUBLIC\GhidraScriptsRepo" -postScript cfg.py -noanalysis

"""

import os
import json
from java.text import SimpleDateFormat
from java.util import Date
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

# global var provided by Ghidra to currently loaded binary
program_name = currentProgram.getName().replace(":", "_")

# create output dir if doesnt already exist
if not os.path.exists(OUT_DIR):
    os.makedirs(OUT_DIR)

# create a semi-variable .json filename to ouput to
timestamp = SimpleDateFormat("HH-mm-ss").format(Date())
out_path = os.path.join(OUT_DIR, program_name + "_cfg_" + timestamp + ".json")



print("\n--- STARTING CFG EXTRACTION ---")

# Ghidra API object responsible for breaking a function down into basic blocks
block_model = BasicBlockModel(currentProgram)
# Ghidra API ops require a monitor to (report progress|cancel long tasks)
## Headless analyzer can use a dummy
monitor = TaskMonitor.DUMMY
# seems to 
listing = currentProgram.getListing()

function_manager = currentProgram.getFunctionManager()
# Fetches an iterator for all recognized functions in the binary, traversing forward through the code
functions = function_manager.getFunctions(True) 

cfg_dataset = {}

for func in functions:
    func_name = func.getName()
    func_body = func.getBody()
    
    # 
    cfg_dataset[func_name] = {
        "nodes": {},
        "edges": []
    }
    
    # Track block entry points explicitly within this function to validate local edges
    local_block_addresses = set()
    # grabs all basic blocks belonging to the current function's body footprint
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    
    # Loop 1: Extract Nodes (Basic Blocks)
    while code_blocks.hasNext():
        block = code_blocks.next()
        block_start = block.getMinAddress().toString()
        local_block_addresses.add(block_start)
        
        cfg_dataset[func_name]["nodes"][block_start] = {
            "label": block.getName(),
            "raw_bytes": [] 
        }
        
        # Pull instruction bytes out of the block (convert from raw signed Java bytes into clean hex strings ex. 0xff )
	# Returns an iter of the instrs in this listing (in proper sequence), starting at the specified address
        ins_iter = listing.getInstructions(block, True)
        while ins_iter.hasNext():
            ins = ins_iter.next()
            java_bytes = ins.getBytes()
            hex_bytes = "".join([format(b & 0xff, '02x') for b in java_bytes])
            cfg_dataset[func_name]["nodes"][block_start]["raw_bytes"].append(hex_bytes)
            
    # Loop 2: Extract Edges (Control Flow Connections)
    # Re-instantiate the iterator to safely run through the blocks a second time
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    while code_blocks.hasNext():
        block = code_blocks.next()
        block_start = block.getMinAddress().toString()
        
	# ask Ghidra where block can branch to next (e.g., jump targets,
	## conditional branch paths, or sequential falls-through).
        destinations = block.getDestinations(monitor)
        while destinations.hasNext():
            reference = destinations.next()
            dest_block_start = reference.getDestinationAddress().toString()
            
            # Determine if this edge jumps out of the current function (e.g., calling an external API or another function ?within same binary?)
            is_local = dest_block_start in local_block_addresses
            
            cfg_dataset[func_name]["edges"].append({
                "source": block_start,
                "target": dest_block_start,
                "flow_type": reference.getFlowType().toString(),
                "is_local": is_local
            })

# ---------- Export to JSON ----------
print("Writing CFG structural graph(s) to: " + out_path)
with open(out_path, 'w') as f:
    json.dump(cfg_dataset, f, indent=4)

print("--- EXTRACTION COMPLETE ---\n")







"""
EXAMPLE OUTPUT

{
    "add": {
        "edges": [], 
        "nodes": {
            "00100000": {
                "label": "add", 
                "raw_bytes": [
                    "55", 
                    "4889e5", 
                    "897dfc", 
                    "8975f8", 
                    "8b45fc", 
                    "0345f8", 
                    "5d", 
                    "c3"
                ]
            }
        }
    }, 
    "subtract": {
        "edges": [], 
        "nodes": {
            "00100070": {
                "label": "subtract", 
                "raw_bytes": [
                    "55", 
                    "4889e5", 
                    "897dfc", 
                    "8975f8", 
                    "8b45fc", 
                    "2b45f8", 
                    "5d", 
                    "c3"
                ]
            }
        }
    }, 
    "math_ops": {
        "edges": [
            {
                "source": "00100090", 
                "target": "00100000", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "00100090", 
                "target": "001000cc", 
                "flow_type": "CONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "00100090", 
                "target": "001000bc", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "001000bc", 
                "target": "00100020", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "001000bc", 
                "target": "001000da", 
                "flow_type": "UNCONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "001000cc", 
                "target": "00100070", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "001000cc", 
                "target": "001000da", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }
        ], 
        "nodes": {
            "001000cc": {
                "label": "LAB_001000cc", 
                "raw_bytes": [
                    "8b7dfc", 
                    "8b75f8", 
                    "e899ffffff", 
                    "8945f0"
                ]
            }, 
            "001000da": {
                "label": "LAB_001000da", 
                "raw_bytes": [
                    "8b45f0", 
                    "4883c410", 
                    "5d", 
                    "c3"
                ]
            }, 
            "00100090": {
                "label": "math_ops", 
                "raw_bytes": [
                    "55", 
                    "4889e5", 
                    "4883ec10", 
                    "897dfc", 
                    "8975f8", 
                    "8b7dfc", 
                    "8b75f8", 
                    "e857ffffff", 
                    "8945f4", 
                    "8b45f4", 
                    "b902000000", 
                    "99", 
                    "f7f9", 
                    "83fa00", 
                    "7510"
                ]
            }, 
            "001000bc": {
                "label": "001000bc", 
                "raw_bytes": [
                    "8b7dfc", 
                    "8b75f8", 
                    "e859ffffff", 
                    "8945f0", 
                    "eb0e"
                ]
            }
        }
    }, 
    "multiplyItself": {
        "edges": [
            {
                "source": "00100020", 
                "target": "0010003c", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "0010003c", 
                "target": "00100060", 
                "flow_type": "CONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "0010003c", 
                "target": "00100044", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "00100044", 
                "target": "00100000", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "00100044", 
                "target": "0010003c", 
                "flow_type": "UNCONDITIONAL_JUMP", 
                "is_local": true
            }
        ], 
        "nodes": {
            "00100060": {
                "label": "LAB_00100060", 
                "raw_bytes": [
                    "8b45f4", 
                    "4883c410", 
                    "5d", 
                    "c3"
                ]
            }, 
            "00100044": {
                "label": "00100044", 
                "raw_bytes": [
                    "8b7dfc", 
                    "8b75fc", 
                    "e8b1ffffff", 
                    "0345f4", 
                    "8945f4", 
                    "8b45f0", 
                    "83c001", 
                    "8945f0", 
                    "ebdc"
                ]
            }, 
            "00100020": {
                "label": "multiplyItself", 
                "raw_bytes": [
                    "55", 
                    "4889e5", 
                    "4883ec10", 
                    "897dfc", 
                    "8975f8", 
                    "c745f400000000", 
                    "c745f000000000"
                ]
            }, 
            "0010003c": {
                "label": "LAB_0010003c", 
                "raw_bytes": [
                    "8b45f0", 
                    "3b45f8", 
                    "7d1c"
                ]
            }
        }
    }
}

"""