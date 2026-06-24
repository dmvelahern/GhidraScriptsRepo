#@category BinKit
#@runtime JYTHON

import os
import json
from java.text import SimpleDateFormat
from java.util import Date
from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import TaskMonitor

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


# global var provided by Ghidra to currently loaded binary
program_name = currentProgram.getName().replace(":", "_")

# create output dir if doesnt already exist
if not os.path.exists(OUT_DIR):
    os.makedirs(OUT_DIR)

# create a semi-variable .json filename to ouput to
timestamp = SimpleDateFormat("HH-mm-ss").format(Date())
out_path = os.path.join(OUT_DIR, program_name + "_normalized_cfg_" + timestamp + ".json")



print("\n--- STARTING CFG EXTRACTION ---")

# Ghidra API object responsible for breaking a function down into basic blocks
block_model = BasicBlockModel(currentProgram)
# Ghidra API ops require a monitor to (report progress|cancel long tasks)
## Headless analyzer can use a dummy
monitor = TaskMonitor.DUMMY
listing = currentProgram.getListing()

function_manager = currentProgram.getFunctionManager()
# Fetches an iterator for all recognized functions in the binary, traversing forward through the code
functions = function_manager.getFunctions(True) 

cfg_dataset = {}

# FOR EACH FUNCTION FOUND IN GIVEN BINARY
for func in functions:
    func_name = func.getName()
    func_body = func.getBody()
    
    cfg_dataset[func_name] = {
        "nodes": {},
        "edges": []
    }
    
    # Track block entry points explicitly within this function to validate local edges
    local_block_addresses = set()
    # grabs all basic blocks belonging to the current function's body footprint
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    
    # --- ADDRESS NORMALIZATION MAPS ---
    ## The prupose of this is to normalize the addresses of the nodes/edges per function
    addr_to_id = {}
    id_counter = 0
    
    # Loop 1: Extract Nodes (Basic Blocks) + Map addresses/Generate Sequential IDs
    while code_blocks.hasNext():
        block = code_blocks.next()
        block_start = block.getMinAddress().toString()
        local_block_addresses.add(block_start)
        
        # Assign a local function ID if we haven't seen this block address yet
        if block_start not in addr_to_id:
            addr_to_id[block_start] = str(id_counter)
            id_counter += 1
            
        local_id = addr_to_id[block_start]
        
        cfg_dataset[func_name]["nodes"][local_id] = {
            "label": block.getName(),
            "raw_address": block_start, # Retained for debugging/traceability
            "raw_bytes": [] 
        }
        

        # Pull instruction bytes out of the block (convert from raw signed Java bytes into clean hex strings ex. 0xff )
	# Returns an iter of the instrs in this listing (in proper sequence), starting at the specified address
        ins_iter = listing.getInstructions(block, True)
        while ins_iter.hasNext():
            ins = ins_iter.next()
            java_bytes = ins.getBytes()
            hex_bytes = "".join([format(b & 0xff, '02x') for b in java_bytes])
            cfg_dataset[func_name]["nodes"][local_id]["raw_bytes"].append(hex_bytes)
            
    # Loop 2: Extract Edges (Control Flow Connections) using Normalized Identifiers
    # Re-instantiate the iterator to safely run through the blocks a second time
    code_blocks = block_model.getCodeBlocksContaining(func_body, monitor)
    while code_blocks.hasNext():
        block = code_blocks.next()
        block_start = block.getMinAddress().toString()
        source_id = addr_to_id[block_start]
        
        # ask Ghidra where block can branch to next (e.g., jump targets,
	## conditional branch paths, or sequential falls-through)
        destinations = block.getDestinations(monitor)
        while destinations.hasNext():
            reference = destinations.next()
            dest_block_start = reference.getDestinationAddress().toString()

	    # Determine if this edge jumps out of the current function (e.g., calling an external API or another function ?within same binary?)
            is_local = dest_block_start in local_block_addresses
            
            # If the edge is local, use its normalized counterpart
            # If it's external (e.g. library call or func not same as current), keep the absolute target string or label it external + vaddr
            if is_local:
                if dest_block_start not in addr_to_id:
                    addr_to_id[dest_block_start] = str(id_counter)
                    id_counter += 1
                target_id = addr_to_id[dest_block_start]
            else:
                # target_id = dest_block_start # Fallback to absolute value for external jumps
		# Try to get the actual function name if Ghidra resolved it, 
    		# otherwise label it as an external address
    		ext_func = function_manager.getFunctionAt(reference.getDestinationAddress())
    		if ext_func:
        		target_id = "EXT_" + ext_func.getName()
    		else:
        		target_id = "EXT_" + dest_block_start
            

	    # Package the edge
            cfg_dataset[func_name]["edges"].append({
                "source": source_id,
                "target": target_id,
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
            "0": {
                "label": "add", 
                "raw_address": "00100000", 
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
            "0": {
                "label": "subtract", 
                "raw_address": "00100070", 
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
                "source": "0", 
                "target": "EXT_add", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "0", 
                "target": "2", 
                "flow_type": "CONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "0", 
                "target": "1", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "1", 
                "target": "EXT_multiplyItself", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "1", 
                "target": "3", 
                "flow_type": "UNCONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "2", 
                "target": "EXT_subtract", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "2", 
                "target": "3", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }
        ], 
        "nodes": {
            "0": {
                "label": "math_ops", 
                "raw_address": "00100090", 
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
            "1": {
                "label": "001000bc", 
                "raw_address": "001000bc", 
                "raw_bytes": [
                    "8b7dfc", 
                    "8b75f8", 
                    "e859ffffff", 
                    "8945f0", 
                    "eb0e"
                ]
            }, 
            "2": {
                "label": "LAB_001000cc", 
                "raw_address": "001000cc", 
                "raw_bytes": [
                    "8b7dfc", 
                    "8b75f8", 
                    "e899ffffff", 
                    "8945f0"
                ]
            }, 
            "3": {
                "label": "LAB_001000da", 
                "raw_address": "001000da", 
                "raw_bytes": [
                    "8b45f0", 
                    "4883c410", 
                    "5d", 
                    "c3"
                ]
            }
        }
    }, 
    "multiplyItself": {
        "edges": [
            {
                "source": "0", 
                "target": "1", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "1", 
                "target": "3", 
                "flow_type": "CONDITIONAL_JUMP", 
                "is_local": true
            }, 
            {
                "source": "1", 
                "target": "2", 
                "flow_type": "FALL_THROUGH", 
                "is_local": true
            }, 
            {
                "source": "2", 
                "target": "EXT_add", 
                "flow_type": "UNCONDITIONAL_CALL", 
                "is_local": false
            }, 
            {
                "source": "2", 
                "target": "1", 
                "flow_type": "UNCONDITIONAL_JUMP", 
                "is_local": true
            }
        ], 
        "nodes": {
            "0": {
                "label": "multiplyItself", 
                "raw_address": "00100020", 
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
            "1": {
                "label": "LAB_0010003c", 
                "raw_address": "0010003c", 
                "raw_bytes": [
                    "8b45f0", 
                    "3b45f8", 
                    "7d1c"
                ]
            }, 
            "2": {
                "label": "00100044", 
                "raw_address": "00100044", 
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
            "3": {
                "label": "LAB_00100060", 
                "raw_address": "00100060", 
                "raw_bytes": [
                    "8b45f4", 
                    "4883c410", 
                    "5d", 
                    "c3"
                ]
            }
        }
    }
}

"""