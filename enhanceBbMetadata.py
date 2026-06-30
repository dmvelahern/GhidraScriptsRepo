
# Purpose: 
# To run Capstone analysis on each basic block in the Ghidra-generated CFG JSON output. 
# This will enrich the dataset with additional metadata like 
# instruction counts, 
# control flow operations, 
# vectorization hints, 
# and immediate constants found in the block

# Example Usage:
# (venv) PS C:\Users\danie\Documents\Tools\GhidraInstallation\ghidra_12.0.4_PUBLIC_20260303\
#     ghidra_12.0.4_PUBLIC\GhidraScriptsRepo> 
#     python .\enhanceBbMetadata.py "C:\Users\danie\Desktop\bcsd\bcsd_GhidraProject\GhidraScriptOutput\test\layers-clang-21_1_8-O0-x86_64.o_normalized_cfg_20-22-16.json"



import json
import binascii
import sys

# Will only focus on x86_64 and aarch64 for now, but can be extended to other architectures
from capstone.x86_const import X86_GRP_RET, X86_GRP_CALL
from capstone.arm64_const import ARM64_GRP_RET, ARM64_GRP_CALL
from capstone import (
    Cs, x86, arm64,
    CS_ARCH_X86, CS_MODE_64,
    CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN
)

ARCH_MAP = {
    "x86_64": (CS_ARCH_X86, CS_MODE_64),
    "arm64":   (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
    "aarch64": (CS_ARCH_ARM64, CS_MODE_LITTLE_ENDIAN),
}

def analyze_block_with_capstone(hex_instruction_list, capstone_engine, arch_str):
    full_hex_string = "".join(hex_instruction_list).strip().lower()
    binary_payload = binascii.unhexlify(full_hex_string)
    
    metrics = {
        "total_instructions": 0,
        "control_flow_ops": 0,    # Calls/Returns
        "vector_simd_ops": 0,     # Advanced loops/vectorization checks (-O3 flag)
        "constants_found": [],    # Immediate values 
        "disassembly": []
    }

    for ins in capstone_engine.disasm(binary_payload, 0x0):
        metrics["total_instructions"] += 1
        metrics["disassembly"].append(f"{ins.mnemonic} {ins.op_str}")
        
        # --- 1. EVALUATE X86_64 ARCHITECTURE DETAILS ---
        if arch_str == "x86_64":
            # Identify high-level instruction groups via native integers
            if X86_GRP_CALL in ins.groups or X86_GRP_RET in ins.groups:
                metrics["control_flow_ops"] += 1
            SIMD_GROUPS = {
                    x86.X86_GRP_MMX,
                    x86.X86_GRP_SSE1,
                    x86.X86_GRP_SSE2,
                    x86.X86_GRP_SSE3,
                    x86.X86_GRP_SSSE3,
                    x86.X86_GRP_SSE41,
                    x86.X86_GRP_SSE42,
                    x86.X86_GRP_SSE4A,
                    x86.X86_GRP_AVX,
                    x86.X86_GRP_AVX2,
                    x86.X86_GRP_AVX512,
            }
            if any(g in ins.groups for g in SIMD_GROUPS):
                metrics["vector_simd_ops"] += 1
                
            # Grab raw constant allocations
            CONTROL_FLOW = {
                x86.X86_GRP_CALL,
                x86.X86_GRP_JUMP,
                x86.X86_GRP_RET,
            }

            is_control_flow = any(g in ins.groups for g in CONTROL_FLOW)
            # dont include constants from control flow instructions (like call 0xdeadbeef) since they are not "data" constants
            if not is_control_flow:
                for op in ins.operands:
                    if op.type == x86.X86_OP_IMM:
                        metrics["constants_found"].append(op.imm)

        # --- 2. EVALUATE ARM64 (AARCH64) ARCHITECTURE DETAILS ---
        elif arch_str in ["aarch64", "arm64"]:
            if ARM64_GRP_CALL in ins.groups or ARM64_GRP_RET in ins.groups:
                metrics["control_flow_ops"] += 1
            SIMD_GROUPS = {
                arm64.ARM64_GRP_NEON,
                arm64.ARM64_GRP_SVE,
                arm64.ARM64_GRP_SVE2,
                arm64.ARM64_GRP_SME,
                arm64.ARM64_GRP_SMEF64,
                arm64.ARM64_GRP_SMEI64,
            }
            if any(g in ins.groups for g in SIMD_GROUPS):
                metrics["vector_simd_ops"] += 1
                
            # Grab raw constant allocations
            CONTROL_FLOW = {
                arm64.ARM64_GRP_CALL,
                arm64.ARM64_GRP_JUMP,
                arm64.ARM64_GRP_RET,
            }

            is_control_flow = any(g in ins.groups for g in CONTROL_FLOW)
            # dont include constants from control flow instructions (like call 0xdeadbeef) since they are not "data" constants
            if not is_control_flow:
                for op in ins.operands:
                    if op.type == arm64.ARM64_OP_IMM:
                        metrics["constants_found"].append(op.imm)

    return metrics


def main():
    # # x86_64 groups
    # print([x for x in dir(x86) if x.startswith("X86_GRP_")])
    # # arm64 groups
    # print("ARM64 Groups:")
    # print([x for x in dir(arm64) if x.startswith("ARM64_GRP_")])

    JSON_DIR = "C:\\Users\\danie\\Desktop\\bcsd\\bcsd_GhidraProject\\GhidraScriptOutput\\test"
    json_path = f"{JSON_DIR}\\layers-clang-21_1_8-O0-x86_64.o_normalized_cfg_20-22-16.json"
    output_path = f"{JSON_DIR}\\ENRICHED_layers-clang-21_1_8-O0-x86_64.o_normalized_cfg_20-22-16.json"

    if len(sys.argv) < 2:
        print("Usage: python enhanceBbMetadata.py <input_json_path>")
        sys.exit(1)

    json_path = sys.argv[1]

    # Auto-generate output path
    if json_path.endswith(".json"):
        output_path = json_path.replace(".json", "_ENRICHED.json")
    else:
        output_path = json_path + "_ENRICHED.json"

    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 1. Resolve target architecture from binary metadata
    metadata = data.get("binary_metadata", {})
    arch_str = metadata.get("arch", "Unknown").lower()
    
    if arch_str not in ARCH_MAP:
        print(f"[-] Critical Error: Architecture '{arch_str}' is unsupported by script's ARCH_MAP.")
        sys.exit(1)
        
    capstone_arch, capstone_mode = ARCH_MAP[arch_str]
    print(f"[+] Automatically resolved capstone config for: {arch_str}")

    # 2. Initialize Capstone Engine Instance Once
    md = Cs(capstone_arch, capstone_mode)
    md.detail = True  # Enable structural grouping checks

    # 3. Walk through your JSON graph maps
    functions_dict = data.get("functions", {})

    for func_name, func_payload in functions_dict.items():
        nodes_dict = func_payload.get("nodes", {})
        
        for node_id, node_payload in nodes_dict.items():
            raw_bytes_list = node_payload.get("raw_bytes", [])
            
            if not raw_bytes_list:
                continue

            try:
                # Pass engine reference safely into the parser loop
                block_analysis = analyze_block_with_capstone(raw_bytes_list, md, arch_str)
                node_payload["node_metadata"] = block_analysis

            except Exception as e:
                print(f"[-] Failed analyzing block {node_id} in {func_name}: {e}")

    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
        
    print(f"[+] Capstone enriched dataset successfully generated at: {output_path}")


if __name__ == "__main__":
    main()