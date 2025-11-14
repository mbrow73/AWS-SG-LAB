#!/usr/bin/env python3
import sys
import glob
import re
from typing import Set, Tuple

def extract_rule_signature(tf_file: str) -> Tuple[str, str, str, str, str]:
    with open(tf_file) as f:
        content = f.read()
    
    sg_id = re.search(r'security_group_id\s*=\s*"(sg-[a-f0-9]+)"', content)
    from_port = re.search(r'from_port\s*=\s*(\d+|null)', content)
    to_port = re.search(r'to_port\s*=\s*(\d+|null)', content)
    protocol = re.search(r'ip_protocol\s*=\s*"([^"]+)"', content)
    
    cidr = re.search(r'cidr_ipv4\s*=\s*"([^"]+)"', content)
    ref_sg = re.search(r'referenced_security_group_id\s*=\s*"([^"]+)"', content)
    pl = re.search(r'prefix_list_id\s*=\s*"([^"]+)"', content)
    
    target = (cidr.group(1) if cidr else 
             ref_sg.group(1) if ref_sg else 
             pl.group(1) if pl else "unknown")
    
    if all([sg_id, from_port, to_port, protocol]):
        return (sg_id.group(1), from_port.group(1), to_port.group(1), 
                protocol.group(1), target)
    return None

def check_duplicates(rules_dir: str) -> bool:
    signatures: Set[Tuple] = set()
    duplicates = []
    
    for tf_file in glob.glob(f"{rules_dir}/**/*.tf", recursive=True):
        sig = extract_rule_signature(tf_file)
        if sig:
            if sig in signatures:
                duplicates.append((tf_file, sig))
            signatures.add(sig)
    
    if duplicates:
        print("❌ DUPLICATE RULES DETECTED:")
        for file, sig in duplicates:
            print(f"  {file}")
            print(f"    SG: {sig[0]}, Ports: {sig[1]}-{sig[2]}, Protocol: {sig[3]}, Target: {sig[4]}")
        return False
    
    print("✅ No duplicates found")
    return True

if __name__ == '__main__':
    rules_dir = sys.argv[1] if len(sys.argv) > 1 else "terraform/rules"
    sys.exit(0 if check_duplicates(rules_dir) else 1)
