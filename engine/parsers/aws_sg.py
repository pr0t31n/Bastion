"""
Bastion engine/parsers/aws_sg.py — AWS Security Group + NACL JSON parser.

2026-06-11 review fix: parses the JSON output of:

  aws ec2 describe-security-groups --output json
  aws ec2 describe-network-acls    --output json

Each Security Group entry contains IpPermissions (inbound) and
IpPermissionsEgress (outbound). Each entry has FromPort/ToPort, IpProtocol,
and IpRanges/UserIdGroupPairs. We flatten one rule per (permission, range)
pair so AuditEngine's permissive-rule and any-any-rule detectors work
unchanged.

NACLs are flattened similarly: one rule per entry with explicit allow/deny.
"""
import json
import re
from typing import List, Optional

from engine.models import FirewallRule, ParseResult
from engine.parsers.base import AbstractParser, VENDOR_PARSERS


class AwsSecurityGroupParser(AbstractParser):
    """Parses `aws ec2 describe-security-groups` JSON output."""

    VENDOR = "aws_sg"

    def parse(self) -> ParseResult:
        body = "\n".join(self.lines) if isinstance(self.lines, list) else (self.lines or "")
        try:
            obj = json.loads(body)
        except json.JSONDecodeError as exc:
            self._error(0, f"JSON parse error: {exc}")
            return ParseResult(vendor=self.VENDOR, hostname="", version="",
                                rules=[], objects={}, object_groups={},
                                nat_rules=[], interfaces=[], services={},
                                errors=[str(exc)], warnings=[], summary={})

        rules: List[FirewallRule] = []
        sgs = obj.get("SecurityGroups") or [obj] if isinstance(obj, dict) else obj
        for sg in sgs:
            sg_id   = sg.get("GroupId", "")
            sg_name = sg.get("GroupName", "")
            vpc_id  = sg.get("VpcId", "")
            for direction, key in [("inbound", "IpPermissions"),
                                     ("outbound", "IpPermissionsEgress")]:
                for perm in sg.get(key) or []:
                    proto = (perm.get("IpProtocol") or "any")
                    if proto == "-1": proto = "any"
                    from_p = perm.get("FromPort", 0) or 0
                    to_p   = perm.get("ToPort", 65535) or 65535
                    # IpRanges (IPv4)
                    for r in perm.get("IpRanges") or []:
                        rules.append(self._mk_rule(
                            sg_id=sg_id, sg_name=sg_name, vpc_id=vpc_id,
                            direction=direction, proto=str(proto),
                            cidr=r.get("CidrIp", "0.0.0.0/0"),
                            from_p=from_p, to_p=to_p,
                            comment=r.get("Description", ""),
                            raw=json.dumps({"sg": sg_id, "perm": perm, "range": r})))
                    # Ipv6Ranges
                    for r in perm.get("Ipv6Ranges") or []:
                        rules.append(self._mk_rule(
                            sg_id=sg_id, sg_name=sg_name, vpc_id=vpc_id,
                            direction=direction, proto=str(proto),
                            cidr=r.get("CidrIpv6", "::/0"),
                            from_p=from_p, to_p=to_p,
                            comment=r.get("Description", ""),
                            raw=json.dumps({"sg": sg_id, "perm": perm, "range": r})))
                    # UserIdGroupPairs (peer SG references)
                    for pair in perm.get("UserIdGroupPairs") or []:
                        rules.append(self._mk_rule(
                            sg_id=sg_id, sg_name=sg_name, vpc_id=vpc_id,
                            direction=direction, proto=str(proto),
                            cidr=f"sg-{pair.get('GroupId','')}",
                            from_p=from_p, to_p=to_p,
                            comment=pair.get("Description", ""),
                            raw=json.dumps({"sg": sg_id, "perm": perm, "pair": pair})))
        return ParseResult(
            vendor=self.VENDOR, hostname=", ".join(sg.get("GroupName", "") for sg in sgs[:3]),
            version="", rules=rules, objects={}, object_groups={},
            nat_rules=[], interfaces=[], services={},
            errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules),
                      "sg_count": len(sgs)},
        )

    def _mk_rule(self, *, sg_id, sg_name, vpc_id, direction, proto, cidr,
                  from_p, to_p, comment, raw) -> FirewallRule:
        return FirewallRule(
            line_no=0, raw_text=raw[:500],
            action="permit",          # SG rules are allow-only
            protocol=proto.lower(),
            src_zone=("internet" if direction == "inbound" else sg_name),
            dst_zone=(sg_name if direction == "inbound" else "internet"),
            src_addresses=[cidr] if direction == "inbound" else [sg_name],
            dst_addresses=[sg_name] if direction == "inbound" else [cidr],
            src_ports=[(0, 65535)],
            dst_ports=[(int(from_p), int(to_p))] if proto != "any" else [(0, 65535)],
            enabled=True, log=False,
            comment=f"{direction} sg={sg_id} ({sg_name}) vpc={vpc_id} {comment}"[:240],
        )


class AwsNaclParser(AbstractParser):
    """Parses `aws ec2 describe-network-acls` JSON output."""

    VENDOR = "aws_nacl"

    def parse(self) -> ParseResult:
        body = "\n".join(self.lines) if isinstance(self.lines, list) else (self.lines or "")
        try:
            obj = json.loads(body)
        except json.JSONDecodeError as exc:
            self._error(0, f"JSON parse error: {exc}")
            return ParseResult(vendor=self.VENDOR, hostname="", version="",
                                rules=[], objects={}, object_groups={},
                                nat_rules=[], interfaces=[], services={},
                                errors=[str(exc)], warnings=[], summary={})
        rules: List[FirewallRule] = []
        nacls = obj.get("NetworkAcls") or [obj] if isinstance(obj, dict) else obj
        for nacl in nacls:
            nacl_id = nacl.get("NetworkAclId", "")
            vpc_id  = nacl.get("VpcId", "")
            for entry in nacl.get("Entries") or []:
                action = "permit" if (entry.get("RuleAction") or "allow") == "allow" else "deny"
                proto  = entry.get("Protocol") or "any"
                if proto == "-1": proto = "any"
                direction = "outbound" if entry.get("Egress") else "inbound"
                cidr = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock") or "any"
                port_range = entry.get("PortRange") or {}
                from_p = port_range.get("From", 0) or 0
                to_p   = port_range.get("To", 65535) or 65535
                rules.append(FirewallRule(
                    line_no=int(entry.get("RuleNumber", 0)),
                    raw_text=json.dumps(entry)[:500],
                    action=action, protocol=str(proto).lower(),
                    src_zone="internet" if direction == "inbound" else nacl_id,
                    dst_zone=nacl_id if direction == "inbound" else "internet",
                    src_addresses=[cidr] if direction == "inbound" else [nacl_id],
                    dst_addresses=[nacl_id] if direction == "inbound" else [cidr],
                    src_ports=[(0, 65535)],
                    dst_ports=[(int(from_p), int(to_p))] if proto != "any" else [(0, 65535)],
                    enabled=True, log=False,
                    comment=f"NACL {nacl_id} VPC {vpc_id} rule {entry.get('RuleNumber','')}",
                ))
        return ParseResult(
            vendor=self.VENDOR,
            hostname=", ".join(n.get("NetworkAclId", "") for n in nacls[:3]),
            version="", rules=rules, objects={}, object_groups={},
            nat_rules=[], interfaces=[], services={}, errors=[], warnings=[],
            summary={"vendor": self.VENDOR, "rule_count": len(rules),
                      "nacl_count": len(nacls)},
        )


VENDOR_PARSERS["aws_sg"]   = AwsSecurityGroupParser
VENDOR_PARSERS["aws_nacl"] = AwsNaclParser
