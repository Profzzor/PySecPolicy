# **User Rights Assignments (Privileges):**
1. **What it is:** It is the direct mapping between an account (a user or group, represented by its **SID**) and the specific privileges it holds (e.g., SeBackupPrivilege, SeDebugPrivilege).
2. **Registry Path:** `HKLM\SECURITY\Policy\Accounts\`
3. **How it's Stored:** Under this key, there are subkeys named after the SIDs of accounts that have been assigned at least one privilege. Inside each SID's key, there is a subkey named **Privilgs** which contains a single binary value. This binary data is a PRIVILEGE_SET structure that lists the LUIDs (Locally Unique Identifiers) of the assigned privileges.

**Structure of User Rights Assignments in the Registry**

The User Rights Assignments are stored within a specific, well-defined structure inside the SECURITY hive. The primary location for this information is the Policy\Accounts key.

**Registry Path:** `HKLM\SECURITY\Policy\Accounts`

![](images/Pasted%20image%2020251115112520.png)

As seen in the screenshot, this key acts as a container. Each direct subkey is named after the Security Identifier (SID) of a user or group that has specific rights or policies assigned to it.

# **The Structure of an Account SID Key (e.g., S-1-5-21...-1001)**

Each SID key under Policy\Accounts represents a single security principal (a user or a group). To find out the friendly name (e.g., "Administrators" or "Profzzor"), this SID must be cross-referenced with the **SAM hive**.

Inside each SID key, you can find up to four important subkeys that store different aspects of the account's policy:

## **1. Privilgs (Privileges)**

- **Purpose:** This is the most critical subkey for our analysis. It stores the specific User Rights (privileges) assigned to the SID.
- **Data Storage:** It contains a single, unnamed (Default) value. The data is in a raw binary format (REG_NONE).
- **Structure:** This binary data is a PRIVILEGE_SET. It starts with a count of the privileges, followed by a series of 12-byte LUID_AND_ATTRIBUTES structures. 
- **Absence:** As shown in the screenshot, some SIDs like S-1-5-32-559 **do not have this key**. This is normal and simply means that account has no privileges assigned to it directly through the Local Security Policy.

## **2. Sid**

- **Purpose:** This subkey contains a (Default) value that stores the raw binary version of the account's SID.
- **Redundancy:** This might seem redundant because the parent key is already named with the SID string. The key name is for registry organization, while this value provides the raw binary SID that can be read programmatically by system services.
- **Absence:** As we discovered during our debugging, **not every account key has this subkey**. For well-known principals (like S-1-1-0, "Everyone"), the system may omit this key, as the SID is globally known. This is why relying on the parent key's name is the most robust way to identify the SID.

## **3. SecDesc (Security Descriptor)**

- **Purpose:** This stores the security permissions for the account object itself.
- **Interpretation:** In simple terms, this data defines who has the right to view or modify this account's properties (like changing its privileges).
- **Structure:** The binary data is a SECURITY_DESCRIPTOR structure. Python script correctly parses this to identify the Owner (usually Administrators), the primary Group (usually SYSTEM), and the DACL (the list of permissions).

## **4. ActSysAc (Account System Access)**

- **Purpose:** This key defines system access rights granted to the account. This is different from privileges.
- **Interpretation:** These are high-level access rights, such as the right to log on locally, log on through Remote Desktop, or log on as a service. While related to privileges, this is a separate mechanism.
- **Absence:** Like the other keys, this is not always present. It only exists if the account has been granted specific system access rights.

# **Manual Analysis of an Account Policy Entry**

##  **Decoding the Privilgs (Privileges) Value**
![](images/Pasted%20image%2020251115113827.png)

This value defines the User Rights Assignments for the account.

**Hex Data:** 
```
01-00-00-00-00-00-00-00-1C-00-00-00-00-00-00-00-00-00-00-00
```

**Structure (PRIVILEGE_SET) Breakdown:**

| ----------- | ----- | ------------------------------------------------------------------------- |
| Bytes       | Value | Interpretation                                                            |
| 01-00-00-00 | 1     | **Privilege Count:** There is 1 privilege assigned to this account.       |
| 00-00-00-00 | 0     | **Control:** A control flag, typically 0.                                 |
| 1C-00-00-00 | 28    | **Privilege 1 LUID (LowPart):** This is the numeric ID for the privilege. |
| 00-00-00-00 | 0     | **Privilege 1 LUID (HighPart):** Almost always 0.                         |
| 00-00-00-00 | 0     | **Privilege 1 Attributes:** Flags indicating if the privilege is enabled. |

**Resulting Privilege:**  
The LUID 28 corresponds to the constant **SeManageVolumePrivilege**. In secpol.msc, this is listed as "Perform volume maintenance tasks"

## **Decoding the SecDesc (Security Descriptor) Value**
![](images/Pasted%20image%2020251115114013.png)

This value defines who has permission to view or edit this account's policy object in the registry.

**Hex Data:**  
```
01-00-04-80-48-00-00-00-58-00-00-00-00-00-00-00-14-00-00-00-02-00-34-00-02-00-00-00-00-00-18-00-0F-00-0F-00-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-00-00-14-00-00-00-02-00-01-01-00-00-00-00-00-01-00-00-00-00-01-02-00-00-00-00-00-05-20-00-00-00-20-02-00-00-01-01-00-00-00-00-00-05-12-00-00-00
```

**Structure (SECURITY_DESCRIPTOR) Breakdown:**

1. **Header (first 20 bytes):**
    - 01: **Revision** (1)
    - 00: Padding
    - 04-80: **Control Flags** (0x8004). This means SE_SELF_RELATIVE (all data is in this one block) and SE_DACL_PRESENT (permissions are defined).
    - 48-00-00-00: **Owner Offset** (0x30 = 48). The Owner's SID starts at the 48th byte.
    - 58-00-00-00: **Group Offset** (0x38 = 56). The Group's SID starts at the 56th byte.
    - 00-00-00-00: **SACL Offset** (0). No auditing list is present.
    - 14-00-00-00: **DACL Offset** (0x14 = 20). The permissions list starts at the 20th byte.
        
2. **DACL (Permissions) at offset 20:**
    - Starts with an ACL header.
    - **ACE 1 (Access Control Entry):**
        - **Type:** ACCESS_ALLOWED_ACE
        - **Mask:** 0x000F000F (a combination of rights, essentially Full Control).
        - **SID:** S-1-5-32-544 (**Administrators**)
    - **ACE 2:**
        - **Type:** ACCESS_ALLOWED_ACE
        - **Mask:** 0x00020000 (WRITE_DAC - change permissions).
        - **SID:** S-1-5-18 (**SYSTEM**)
3. **Owner SID at offset 48:**
    - Binary data decodes to S-1-5-32-544 (**Administrators**).
4. **Group SID at offset 56:**
    - Binary data decodes to S-1-5-18 (**SYSTEM**).

**Resulting Interpretation:**  
The security descriptor for this policy object specifies that the Administrators group is the owner and has full control, and the SYSTEM account can also change its permissions.
## **Decoding the Sid Value**
![](images/Pasted%20image%2020251115113604.png)

This value contains the binary representation of the account's Security Identifier.

**Hex Data:**  
```
01-05-00-00-00-00-00-05-15-00-00-00-B2-B0-FA-34-81-FA-4D-53-78-D1-55-EF-E9-03-00-00
```

**Structure Breakdown:**

| ----------------- | ---------- | ------------------------------------------------------------------------------ |
| Bytes             | Value      | Interpretation                                                                 |
| 01                | 1          | **Revision:** Always 1.                                                        |
| 05                | 5          | **Sub-Authority Count:** The number of dash-separated values that will follow. |
| 00-00-00-00-00-05 | 5          | **Identifier Authority:** The value 5 represents NT AUTHORITY.                 |
| 15-00-00-00       | 21         | **Sub-Authority 1:** (Little-endian 0x00000015)                                |
| B2-B0-FA-34       | 888844466  | **Sub-Authority 2:** (Little-endian 0x34FAB0B2)                                |
| 81-FA-4D-53       | 1397619329 | **Sub-Authority 3:** (Little-endian 0x534DFA81)                                |
| 78-D1-55-EF       | 4015378808 | **Sub-Authority 4:** (Little-endian 0xEF55D178)                                |
| E9-03-00-00       | 1001       | **Sub-Authority 5 (RID):** (Little-endian 0x000003E9) The Relative ID.         |
**Resulting SID String:** `S-1-5-21-888844466-1397619329-4015378808-1001`

## **Decoding the ActSysAc Value**
In addition to privileges (Privilgs), the Policy\Accounts key also stores system-level logon rights in the ActSysAc subkey. These rights are distinct from Se... privileges and control how an account is allowed to interact with the system.
![](images/Pasted%20image%2020251115114443.png)

**Hex Data:**  
```
D1-00-00-00
```

**Structure Breakdown:**

1. **Endianness:** The data is a 4-byte little-endian DWORD (unsigned integer). To read it, we reverse the byte order.
    - D1 00 00 00 becomes 0x000000D1.
2. **Bitmask:** This value is a bitmask. Each bit represents a specific logon right. To decode it, we break the hexadecimal value 0xD1 into its component bits:
    - 0xD1 = 0x80 + 0x40 + 0x10 + 0x01
3. **Mapping Bits to Logon Rights:** Each of these hex values corresponds to a specific system access right.

|---|---|---|---|
|Bit Value (Hex)|Binary Representation|Logon Right (in secpol.msc)|Interpretation|
|0x01|...0000 0001|**Allow log on locally**|This account is permitted to log on directly at the machine's console.|
|0x10|...0001 0000|**Deny log on as a service**|This account is explicitly forbidden from being used as a service account.|
|0x40|...0100 0000|**Deny access this computer from the network**|This account cannot be used to connect to network shares or other network services on this machine.|
|0x80|...1000 0000|**Deny log on as a batch job**|This account cannot be used to run scheduled tasks or other batch processes.|

**Resulting Interpretation:**
The value 0xD1 for the SID ...-501 (Guest account) means that this account has the following logon rights configured:

- It **is allowed** to log on locally.
- It **is denied** the right to log on as a service.
- It **is denied** the right to access the computer from the network.
- It **is denied** the right to log on as a batch job.

This combination of rights is the standard, default security policy for the built-in Guest account in Windows, designed to restrict its capabilities significantly.

## Bitmask Mapping

| --------------- | ----------------------------- | --------------------------------- |
| Bit Value (Hex) | Flag Name                     | Official Microsoft Constant       |
| 0x00000001      | INTERACTIVE_LOGON             | SeInteractiveLogonRight           |
| 0x00000002      | NETWORK_LOGON                 | SeNetworkLogonRight               |
| 0x00000004      | BATCH_LOGON                   | SeBatchLogonRight                 |
| 0x00000008      | SERVICE_LOGON                 | SeServiceLogonRight               |
| 0x00000020      | DENY_INTERACTIVE_LOGON        | SeDenyInteractiveLogonRight       |
| 0x00000040      | DENY_NETWORK_LOGON            | SeDenyNetworkLogonRight           |
| 0x00000080      | DENY_BATCH_LOGON              | SeDenyBatchLogonRight             |
| 0x00000100      | DENY_SERVICE_LOGON            | SeDenyServiceLogonRight           |
| 0x00000200      | REMOTE_INTERACTIVE_LOGON      | SeRemoteInteractiveLogonRight     |
| 0x00000400      | DENY_REMOTE_INTERACTIVE_LOGON | SeDenyRemoteInteractiveLogonRight |

# Reference
1. [privilegeType Simple Type - Win32 apps | Microsoft Learn](https://learn.microsoft.com/en-us/windows/win32/taskschd/taskschedulerschema-privilegetype-simpletype?source=recommendations)
2. [wine/include/winnt.h at master · wine-mirror/wine · GitHub](https://github.com/wine-mirror/wine/blob/master/include/winnt.h)
