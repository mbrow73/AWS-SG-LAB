#!/usr/bin/env python3
import sys
import re
import ipaddress
import yaml
from typing import Dict, List, Any, Tuple

class ValidationError(Exception):
    pass

def validate_aws_id(value: str, resource_type: str, field_name: str) -> None:
    patterns = {
        'vpc': r'^vpc-[a-f0-9]{8,17}$',
        'sg': r'^sg-[a-f0-9]{8,17}$',
        'pl': r'^pl-[a-f0-9]{8,17}$'
    }
    if not re.match(patterns[resource_type], value):
        raise ValidationError(f"{field_name} must be valid {resource_type} ID format")

def validate_port(port: int, field_name: str) -> None:
    if port != -1 and not (0 <= port <= 65535):
        raise ValidationError(f"{field_name} must be -1 or 0-65535")

def validate_cidr(cidr: str, version: int = 4) -> None:
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        if (version == 4 and net.version != 4) or (version == 6 and net.version != 6):
            raise ValidationError(f"CIDR {cidr} is not IPv{version}")
    except ValueError as e:
        raise ValidationError(f"Invalid CIDR: {cidr} - {str(e)}")

def validate_protocol(protocol: str, protocol_number: str = None) -> str:
    valid_protocols = ['tcp', 'udp', 'icmp', 'icmpv6', 'all', '-1']
    
    if protocol in valid_protocols:
        return protocol if protocol != 'all' else '-1'
    
    if protocol_number:
        try:
            num = int(protocol_number)
            if 0 <= num <= 255:
                return str(num)
        except ValueError:
            pass
        raise ValidationError(f"Protocol number must be 0-255")
    
    raise ValidationError(f"Invalid protocol: {protocol}")

def parse_issue_body(issue_body: str) -> Dict[str, Any]:
    data = {}
    current_field = None
    current_value = []
    
    for line in issue_body.split('\n'):
        if line.startswith('### '):
            if current_field and current_value:
                data[current_field] = '\n'.join(current_value).strip()
            current_field = line[4:].strip()
            current_value = []
        elif current_field and line.strip() and not line.startswith('_No response_'):
            current_value.append(line.strip())
    
    if current_field and current_value:
        data[current_field] = '\n'.join(current_value).strip()
    
    return data

def validate_rule_config(config: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    errors = []
    warnings = []
    validated = {}
    
    try:
        validate_aws_id(config.get('VPC ID', ''), 'vpc', 'VPC ID')
        validated['vpc_id'] = config['VPC ID']
    except ValidationError as e:
        errors.append(str(e))
    
    try:
        validate_aws_id(config.get('Security Group ID', ''), 'sg', 'Security Group ID')
        validated['security_group_id'] = config['Security Group ID']
    except ValidationError as e:
        errors.append(str(e))
    
    rule_type = config.get('Rule Type', '').strip()
    if rule_type not in ['sg_to_cidr', 'sg_to_sg', 'sg_to_prefix_list']:
        errors.append(f"Invalid rule type: {rule_type}")
    validated['rule_type'] = rule_type
    
    direction = config.get('Direction', '').strip().lower()
    if direction not in ['ingress', 'egress']:
        errors.append(f"Invalid direction: {direction}")
    validated['direction'] = direction
    
    try:
        from_port = int(config.get('From Port', ''))
        to_port = int(config.get('To Port', ''))
        validate_port(from_port, 'From Port')
        validate_port(to_port, 'To Port')
        
        if from_port != -1 and to_port != -1 and from_port > to_port:
            errors.append("From Port cannot be greater than To Port")
        
        validated['from_port'] = from_port
        validated['to_port'] = to_port
    except (ValueError, ValidationError) as e:
        errors.append(f"Port validation failed: {str(e)}")
    
    try:
        protocol = config.get('Protocol', '').strip().lower()
        protocol_number = config.get('Protocol Number (if custom)', '').strip()
        validated['protocol'] = validate_protocol(protocol, protocol_number if protocol_number else None)
    except ValidationError as e:
        errors.append(str(e))
    
    if rule_type == 'sg_to_cidr':
        cidr_input = config.get('CIDR Blocks (for sg_to_cidr only)', '')
        ipv6_input = config.get('IPv6 CIDR Blocks (for sg_to_cidr only)', '')
        
        cidrs = [c.strip() for c in cidr_input.split('\n') if c.strip()]
        ipv6_cidrs = [c.strip() for c in ipv6_input.split('\n') if c.strip()]
        
        if not cidrs and not ipv6_cidrs:
            errors.append("sg_to_cidr requires at least one CIDR block")
        
        for cidr in cidrs:
            try:
                validate_cidr(cidr, 4)
            except ValidationError as e:
                errors.append(str(e))
        
        for cidr in ipv6_cidrs:
            try:
                validate_cidr(cidr, 6)
            except ValidationError as e:
                errors.append(str(e))
        
        if any(c in ['0.0.0.0/0'] for c in cidrs):
            warnings.append("⚠️  Rule allows traffic from 0.0.0.0/0 (entire internet)")
        
        validated['cidr_blocks'] = cidrs
        validated['ipv6_cidr_blocks'] = ipv6_cidrs
    
    elif rule_type == 'sg_to_sg':
        source_sg = config.get('Source Security Group ID (for sg_to_sg only)', '').strip()
        if not source_sg:
            errors.append("sg_to_sg requires Source Security Group ID")
        else:
            try:
                validate_aws_id(source_sg, 'sg', 'Source Security Group ID')
                validated['source_security_group_id'] = source_sg
            except ValidationError as e:
                errors.append(str(e))
    
    elif rule_type == 'sg_to_prefix_list':
        pl_id = config.get('Prefix List ID (for sg_to_prefix_list only)', '').strip()
        if not pl_id:
            errors.append("sg_to_prefix_list requires Prefix List ID")
        else:
            try:
                validate_aws_id(pl_id, 'pl', 'Prefix List ID')
                validated['prefix_list_id'] = pl_id
            except ValidationError as e:
                errors.append(str(e))
    
    desc = config.get('Rule Description', '').strip()
    if not desc or len(desc) < 10:
        errors.append("Rule Description must be at least 10 characters")
    validated['description'] = desc
    
    justification = config.get('Business Justification', '').strip()
    if not justification or len(justification) < 20:
        errors.append("Business Justification must be at least 20 characters")
    validated['business_justification'] = justification
    
    requested_by = config.get('Requested By', '').strip()
    if not requested_by:
        errors.append("Requested By is required")
    validated['requested_by'] = requested_by
    
    return validated, errors, warnings

def generate_terraform_file(validated: Dict[str, Any], existing_rules: List[Dict]) -> str:
    rule_id = f"{validated['rule_type']}_{validated['direction']}_{validated['from_port']}_{validated['to_port']}"
    
    for existing in existing_rules:
        if (existing.get('direction') == validated['direction'] and 
            existing.get('from_port') == validated['from_port'] and
            existing.get('to_port') == validated['to_port'] and
            existing.get('protocol') == validated['protocol']):
            
            if validated['rule_type'] == 'sg_to_cidr':
                if set(validated.get('cidr_blocks', [])) & set(existing.get('cidr_blocks', [])):
                    raise ValidationError("Duplicate rule detected with overlapping CIDR blocks")
            elif validated['rule_type'] == 'sg_to_sg':
                if validated.get('source_security_group_id') == existing.get('source_security_group_id'):
                    raise ValidationError("Duplicate rule detected with same source security group")
    
    tf_lines = [f'# {validated["description"]}', f'# Requested by: {validated["requested_by"]}']
    
    if validated['rule_type'] == 'sg_to_cidr':
        if validated.get('cidr_blocks'):
            tf_lines.extend([
                f'resource "aws_vpc_security_group_ingress_rule" "{rule_id}_ipv4" {{',
                f'  security_group_id = "{validated["security_group_id"]}"',
                f'  description       = "{validated["description"]}"',
                f'  from_port         = {validated["from_port"]}',
                f'  to_port           = {validated["to_port"]}',
                f'  ip_protocol       = "{validated["protocol"]}"',
                f'  cidr_ipv4         = "{validated["cidr_blocks"][0]}"',
                '}', ''
            ])
    
    elif validated['rule_type'] == 'sg_to_sg':
        tf_lines.extend([
            f'resource "aws_vpc_security_group_{validated["direction"]}_rule" "{rule_id}" {{',
            f'  security_group_id            = "{validated["security_group_id"]}"',
            f'  description                  = "{validated["description"]}"',
            f'  from_port                    = {validated["from_port"]}',
            f'  to_port                      = {validated["to_port"]}',
            f'  ip_protocol                  = "{validated["protocol"]}"',
            f'  referenced_security_group_id = "{validated["source_security_group_id"]}"',
            '}', ''
        ])
    
    elif validated['rule_type'] == 'sg_to_prefix_list':
        tf_lines.extend([
            f'resource "aws_vpc_security_group_{validated["direction"]}_rule" "{rule_id}" {{',
            f'  security_group_id = "{validated["security_group_id"]}"',
            f'  description       = "{validated["description"]}"',
            f'  from_port         = {validated["from_port"]}',
            f'  to_port           = {validated["to_port"]}',
            f'  ip_protocol       = "{validated["protocol"]}"',
            f'  prefix_list_id    = "{validated["prefix_list_id"]}"',
            '}', ''
        ])
    
    return '\n'.join(tf_lines)

def main():
    if len(sys.argv) < 2:
        print("Usage: validate.py <issue_body_file>")
        sys.exit(1)
    
    with open(sys.argv[1], 'r') as f:
        issue_body = f.read()
    
    config = parse_issue_body(issue_body)
    
    try:
        validated, errors, warnings = validate_rule_config(config)
        
        if errors:
            print("❌ VALIDATION FAILED\n")
            print("Errors:")
            for error in errors:
                print(f"  • {error}")
            sys.exit(1)
        
        if warnings:
            print("⚠️  WARNINGS\n")
            for warning in warnings:
                print(f"  {warning}")
            print()
        
        print("✅ VALIDATION PASSED\n")
        print("Validated Configuration:")
        print(yaml.dump(validated, default_flow_style=False, sort_keys=False))
        
        with open('/tmp/validated_config.yml', 'w') as f:
            yaml.dump(validated, f, default_flow_style=False, sort_keys=False)
        
        print("\nValidated configuration saved to /tmp/validated_config.yml")
        
    except ValidationError as e:
        print(f"❌ VALIDATION FAILED: {str(e)}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ UNEXPECTED ERROR: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
