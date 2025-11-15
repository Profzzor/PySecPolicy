import struct
import sys
import os

# System Access flags
SYSTEM_ACCESS_FLAGS = {
    0x00000001: "INTERACTIVE_LOGON",
    0x00000002: "NETWORK_LOGON",
    0x00000004: "BATCH_LOGON",
    0x00000008: "SERVICE_LOGON",
    0x00000010: "PROXY_LOGON",
    0x00000020: "DENY_INTERACTIVE_LOGON",
    0x00000040: "DENY_NETWORK_LOGON",
    0x00000080: "DENY_BATCH_LOGON",
    0x00000100: "DENY_SERVICE_LOGON",
    0x00000200: "REMOTE_INTERACTIVE_LOGON",
    0x00000400: "DENY_REMOTE_INTERACTIVE_LOGON",
}
PRIVILEGE_NAMES = {
    2: "SeCreateTokenPrivilege",
    3: "SeAssignPrimaryTokenPrivilege",
    4: "SeLockMemoryPrivilege",
    5: "SeIncreaseQuotaPrivilege",
    6: "SeMachineAccountPrivilege",
    7: "SeTcbPrivilege",
    8: "SeSecurityPrivilege",
    9: "SeTakeOwnershipPrivilege",
    10: "SeLoadDriverPrivilege",
    11: "SeSystemProfilePrivilege",
    12: "SeSystemtimePrivilege",
    13: "SeProfileSingleProcessPrivilege",
    14: "SeIncreaseBasePriorityPrivilege",
    15: "SeCreatePagefilePrivilege",
    16: "SeCreatePermanentPrivilege",
    17: "SeBackupPrivilege",
    18: "SeRestorePrivilege",
    19: "SeShutdownPrivilege",
    20: "SeDebugPrivilege",
    21: "SeAuditPrivilege",
    22: "SeSystemEnvironmentPrivilege",
    23: "SeChangeNotifyPrivilege",
    24: "SeRemoteShutdownPrivilege",
    25: "SeUndockPrivilege",
    26: "SeSyncAgentPrivilege",
    27: "SeEnableDelegationPrivilege",
    28: "SeManageVolumePrivilege",
    29: "SeImpersonatePrivilege",
    30: "SeCreateGlobalPrivilege",
    31: "SeTrustedCredManAccessPrivilege",
    32: "SeRelabelPrivilege",
    33: "SeIncreaseWorkingSetPrivilege",
    34: "SeTimeZonePrivilege",
    35: "SeCreateSymbolicLinkPrivilege",
}

def parse_system_access(data):
    """Parse ActSysAc (Active System Access) value"""
    if len(data) < 4:
        print("  [!] Data too short for System Access")
        return
    
    access_flags = struct.unpack('<I', data[0:4])[0]
    print(f"  System Access Flags: 0x{access_flags:08X} ({access_flags})")
    
    active_flags = []
    for flag, name in SYSTEM_ACCESS_FLAGS.items():
        if access_flags & flag:
            active_flags.append(name)
    
    if active_flags:
        print(f"  Active permissions:")
        for flag_name in active_flags:
            print(f"    - {flag_name}")
    else:
        print(f"  No standard flags set")

    """Parse PRIVILEGE_SET structure"""
    if len(data) < 8:
        print("  [!] Data too short for PRIVILEGE_SET")
        return
    
    priv_count = struct.unpack('<I', data[0:4])[0]
    control = struct.unpack('<I', data[4:8])[0]
    
    print(f"  Privilege Count: {priv_count}")
    print(f"  Control: 0x{control:08X}")
    
    if priv_count == 0:
        print("  No privileges assigned")
        return
    
    offset = 8
    for i in range(priv_count):
        if offset + 12 > len(data):
            print(f"  [!] Insufficient data for privilege {i+1}")
            break
            
        luid_low = struct.unpack('<I', data[offset:offset+4])[0]
        luid_high = struct.unpack('<I', data[offset+4:offset+8])[0]
        attributes = struct.unpack('<I', data[offset+8:offset+12])[0]
        
        priv_name = PRIVILEGE_NAMES.get(luid_low, f"Unknown (LUID {luid_low})")
        
        print(f"  Privilege {i+1}:")
        print(f"    LUID: 0x{luid_low:08X} (decimal: {luid_low})")
        print(f"    Name: {priv_name}")
        print(f"    Attributes: 0x{attributes:08X}")
        
        offset += 12

def parse_sid(data):
    """Parse Security Identifier (SID)"""
    if len(data) < 8:
        return "Invalid SID"
    
    # Debug: print hex dump
    hex_dump = '-'.join(f'{b:02X}' for b in data)
    print(f"  DEBUG Hex: {hex_dump}")
    
    revision = data[0]
    sub_auth_count = data[1]
    # Authority is big-endian (network byte order)
    authority = struct.unpack('>Q', b'\x00\x00' + data[2:8])[0]
    
    if len(data) < 8 + (sub_auth_count * 4):
        return "Invalid SID (truncated)"
    
    sub_authorities = []
    for i in range(sub_auth_count):
        offset = 8 + (i * 4)
        # Sub-authorities are little-endian
        sub_auth = struct.unpack('<I', data[offset:offset+4])[0]
        print(f"  DEBUG Sub-auth {i+1}: bytes={data[offset:offset+4].hex()} value={sub_auth}")
        sub_authorities.append(sub_auth)
    
    sid_string = f"S-{revision}-{authority}"
    for sub_auth in sub_authorities:
        sid_string += f"-{sub_auth}"
    
    return sid_string

def parse_security_descriptor(data):
    """Parse SECURITY_DESCRIPTOR structure"""
    if len(data) < 20:
        print("  [!] Data too short for SECURITY_DESCRIPTOR")
        return
    
    revision = data[0]
    sbz1 = data[1]
    control = struct.unpack('<H', data[2:4])[0]
    owner_offset = struct.unpack('<I', data[4:8])[0]
    group_offset = struct.unpack('<I', data[8:12])[0]
    sacl_offset = struct.unpack('<I', data[12:16])[0]
    dacl_offset = struct.unpack('<I', data[16:20])[0]
    
    print(f"  Revision: {revision}")
    print(f"  Control: 0x{control:04X}")
    
    # Decode control flags
    flags = []
    if control & 0x0001: flags.append("SE_OWNER_DEFAULTED")
    if control & 0x0002: flags.append("SE_GROUP_DEFAULTED")
    if control & 0x0004: flags.append("SE_DACL_PRESENT")
    if control & 0x0008: flags.append("SE_DACL_DEFAULTED")
    if control & 0x0010: flags.append("SE_SACL_PRESENT")
    if control & 0x0020: flags.append("SE_SACL_DEFAULTED")
    if control & 0x8000: flags.append("SE_SELF_RELATIVE")
    
    print(f"  Flags: {', '.join(flags)}")
    
    # Parse DACL
    if dacl_offset > 0 and dacl_offset < len(data):
        print(f"  DACL present at offset {dacl_offset}")
        parse_acl(data, dacl_offset, "DACL")
    
    # Parse Owner SID
    if owner_offset > 0 and owner_offset < len(data):
        owner_sid = parse_sid(data[owner_offset:])
        print(f"  Owner SID: {owner_sid}")
    
    # Parse Group SID
    if group_offset > 0 and group_offset < len(data):
        group_sid = parse_sid(data[group_offset:])
        print(f"  Group SID: {group_sid}")

def parse_acl(data, offset, acl_type):
    """Parse ACL (Access Control List)"""
    if offset + 8 > len(data):
        print(f"    [!] Insufficient data for {acl_type}")
        return
    
    acl_revision = data[offset]
    sbz1 = data[offset + 1]
    acl_size = struct.unpack('<H', data[offset+2:offset+4])[0]
    ace_count = struct.unpack('<H', data[offset+4:offset+6])[0]
    
    print(f"    ACL Size: {acl_size} bytes")
    print(f"    ACE Count: {ace_count}")
    
    ace_offset = offset + 8
    for i in range(ace_count):
        if ace_offset + 8 > len(data):
            print(f"    [!] Insufficient data for ACE {i+1}")
            break
            
        ace_type = data[ace_offset]
        ace_flags = data[ace_offset + 1]
        ace_size = struct.unpack('<H', data[ace_offset+2:ace_offset+4])[0]
        access_mask = struct.unpack('<I', data[ace_offset+4:ace_offset+8])[0]
        
        print(f"    ACE {i+1}:")
        print(f"      Type: {get_ace_type_name(ace_type)}")
        print(f"      Flags: 0x{ace_flags:02X}")
        print(f"      Access Mask: 0x{access_mask:08X}")
        
        # Parse SID in ACE
        sid_offset = ace_offset + 8
        if sid_offset < len(data):
            sid_string = parse_sid(data[sid_offset:])
            print(f"      SID: {sid_string}")
        
        ace_offset += ace_size

def get_ace_type_name(ace_type):
    """Get ACE type name"""
    ace_types = {
        0x00: "ACCESS_ALLOWED_ACE",
        0x01: "ACCESS_DENIED_ACE",
        0x02: "SYSTEM_AUDIT_ACE",
        0x03: "SYSTEM_ALARM_ACE",
    }
    return ace_types.get(ace_type, f"Unknown (0x{ace_type:02X})")

def parse_registry_hive(hive_path):
    """Parse security hive file using python-registry or regipy"""
    try:
        from Registry import Registry
        
        print(f"[*] Loading registry hive: {hive_path}")
        reg = Registry.Registry(hive_path)
        
        # Navigate to Policy\Accounts
        try:
            policy_key = reg.open("Policy\\Accounts")
            print(f"[+] Found Policy\\Accounts key")
            print(f"[+] Subkeys: {len(list(policy_key.subkeys()))}")
            print()
            
            # Iterate through each SID subkey
            for subkey in policy_key.subkeys():
                sid_key = subkey.name()
                print(f"=" * 70)
                print(f"[*] Processing: {sid_key}")
                print(f"=" * 70)
                print(f"SID: {sid_key}")
                print()
                
                # Check for ActSysAc subkey
                try:
                    actsysac_subkey = reg.open(f"Policy\\Accounts\\{sid_key}\\ActSysAc")
                    # Read the default value or first value
                    for value in actsysac_subkey.values():
                        actsysac_data = value.value()
                        print(f"\n[ActSysAc] ({len(actsysac_data)} bytes)")
                        parse_system_access(actsysac_data)
                        break
                except Registry.RegistryKeyNotFoundException:
                    print("\n  No ActSysAc subkey found")
                
                # Check for Privilgs subkey
                try:
                    privilgs_subkey = reg.open(f"Policy\\Accounts\\{sid_key}\\Privilgs")
                    # Read the default value or first value
                    for value in privilgs_subkey.values():
                        priv_data = value.value()
                        print(f"\n[Privilgs] ({len(priv_data)} bytes)")
                        parse_system_access(priv_data)
                        break
                except Registry.RegistryKeyNotFoundException:
                    print("\n  No Privilgs subkey found")
                
                # Check for SecDesc subkey
                try:
                    secdesc_subkey = reg.open(f"Policy\\Accounts\\{sid_key}\\SecDesc")
                    # Read the default value or first value
                    for value in secdesc_subkey.values():
                        secdesc_data = value.value()
                        print(f"\n[SecDesc] ({len(secdesc_data)} bytes)")
                        parse_security_descriptor(secdesc_data)
                        break
                except Registry.RegistryKeyNotFoundException:
                    print("  No SecDesc subkey found")
                
                # Check for Sid subkey
                try:
                    sid_subkey = reg.open(f"Policy\\Accounts\\{sid_key}\\Sid")
                    # Read the default value or first value
                    for value in sid_subkey.values():
                        sid_data = value.value()
                        print(f"\n[Sid] ({len(sid_data)} bytes)")
                        # Debug: Print hex dump
                        hex_dump = ' '.join(f'{b:02X}' for b in sid_data)
                        print(f"  Hex: {hex_dump}")
                        sid_string = parse_sid(sid_data)
                        print(f"  SID from value: {sid_string}")
                        if sid_string != sid_key:
                            print(f"  [!] Warning: SID value doesn't match key name")
                            print(f"  [!] Expected: {sid_key}")
                        break
                except Registry.RegistryKeyNotFoundException:
                    print("  No Sid subkey found")
                
                print()
                
        except Registry.RegistryKeyNotFoundException:
            print("[!] Could not find Policy\\Accounts key in hive")
            print("[*] Available root keys:")
            for subkey in reg.root().subkeys():
                print(f"  - {subkey.name()}")
                
    except ImportError:
        print("[!] python-registry library not found.")
        print("[!] Install it with: pip install python-registry")
        print()
        print("[*] Alternative: Install regipy with: pip install regipy")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error parsing registry hive: {e}")
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py <SECURITY_HIVE_PATH>")
        print()
        print("Example:")
        print("  python script.py C:\\Windows\\System32\\config\\SECURITY")
        print("  python script.py ./SECURITY")
        sys.exit(1)
    
    hive_path = sys.argv[1]
    
    if not os.path.exists(hive_path):
        print(f"[!] File not found: {hive_path}")
        sys.exit(1)
    
    parse_registry_hive(hive_path)

if __name__ == "__main__":
    main()
