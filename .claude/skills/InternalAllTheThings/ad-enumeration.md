# AD Enumeration

## BloodHound Data Collection

### Collectors
```ps1
# Python (remote, from Linux)
bloodhound-python -d domain.local -u user -p pass -gc DC.domain.local -c all
pip install bloodhound

# SharpHound (on Windows)
.\SharpHound.exe -c all -d domain.local --searchforest
.\SharpHound.exe -c all,GPOLocalGroup
.\SharpHound.exe --CollectionMethod DCOnly  # stealth - DC only
.\SharpHound.exe -c all --LdapUsername <user> --LdapPassword <pass> --domaincontroller 10.10.10.10
.\SharpHound.exe -c All,GPOLocalGroup --outputdirectory C:\Windows\Temp --randomfilenames --throttle 10000 --jitter 23

# PowerShell
Invoke-BloodHound -SearchForest -CSVFolder C:\Users\Public
Invoke-BloodHound -CollectionMethod All -LDAPUser <user> -LDAPPass <pass>

# RustHound (Rust, Windows/Linux)
rusthound.exe -d domain.local --ldapfqdn domain
rusthound.exe -d domain.local -u user@domain.local -p Pass123 -o output -z

# SOAPHound (C#, ADWS)
SOAPHound.exe --buildcache -c c:\temp\cache.txt
SOAPHound.exe -c c:\temp\cache.txt --bhdump -o c:\temp\output

# Certipy (certificates)
certipy find 'corp.local/john:Pass@dc.corp.local' -bloodhound
certipy find 'corp.local/john:Pass@dc.corp.local' -vulnerable
```

### BloodHound Setup
```ps1
# Docker (CE)
git clone https://github.com/SpecterOps/BloodHound
cd examples/docker-compose/
cat docker-compose.yml | docker compose -f - up
# UI: http://localhost:8080/ui/login

# Classic
neo4j console
./bloodhound --no-sandbox
# http://127.0.0.1:7474  db:bolt://localhost:7687  user:neo4j  pass:neo4j
```

### Useful Cypher Queries
```cypher
-- Unconstrained delegation computers
MATCH (c:Computer {unconstraineddelegation:true}) RETURN c
-- Constrained delegation
MATCH p = (a)-[:AllowedToDelegate]->(c:Computer) RETURN p
-- Kerberoastable users
MATCH (u:User {hasspn:true}) RETURN u
-- ADCS ESC15
MATCH p=(:Base)-[:MemberOf*0..]->()-[:Enroll|AllExtendedRights]->(ct:CertTemplate)-[:PublishedTo]->(:EnterpriseCA) WHERE ct.enrolleesuppliessubject = True AND ct.schemaversion = 1 RETURN p
```

## PowerView Enumeration

```ps1
Import-Module .\PowerView.ps1

# Domain basics
Get-NetDomain; Get-NetDomain -Domain child.domain.local
Get-DomainSID
Get-NetDomainController; Get-NetDomainController -Domain <name>

# Users
Get-NetUser; Get-NetUser -SamAccountName admin
Get-NetUser | select cn
Get-UserProperty -Properties pwdlastset
Find-UserField -SearchField Description -SearchTerm "pass"
Get-NetLoggedon -ComputerName TARGET
Get-NetSession -ComputerName TARGET
Find-DomainUserLocation -Domain <name> | Select-Object UserName, SessionFromName

# Computers
Get-NetComputer -FullData; Get-NetComputer -Ping

# Groups
Get-NetGroupMember -GroupName "Domain Admins" -Domain domain.local
Get-DomainGroup -Identity "Enterprise Admins" | Select-Object -ExpandProperty Member
Get-DomainGPOLocalGroup | Select-Object GPODisplayName, GroupName

# ACLs
Get-ObjectAcl -SamAccountName <account> -ResolveGUIDs
Invoke-ACLScanner -ResolveGUIDs  # find interesting ACEs
Get-PathAcl -Path "\\server\share"

# Shares
Find-DomainShare; Find-DomainShare -CheckShareAccess

# GPO
Get-NetGPO; Get-NetGPO -ComputerName TARGET
Get-NetGPOGroup
Find-GPOComputerAdmin -ComputerName TARGET

# OU
Get-NetOU -FullData

# Trust
Get-NetDomainTrust; Get-NetDomainTrust -Domain <name>
Get-NetForestDomain; Get-NetForestTrust

# User hunting (find DA sessions)
Find-LocalAdminAccess -Verbose
Invoke-UserHunter
Invoke-UserHunter -GroupName "RDPUsers"
Invoke-UserHunter -CheckAccess  # confirm admin access
```

## AD Module (Native PowerShell)

```ps1
# Domain
Get-ADDomain; Get-ADDomain -Identity child.domain.local
Get-ADDomainController; Get-ADDomainController -Identity DC01

# Users
Get-ADUser -Filter * -Properties *
Get-ADUser -Filter 'Description -like "*pass*"' -Properties Description | select Name,Description

# Computers/Groups
Get-ADComputer -Filter * -Properties *
Get-ADGroup -Filter *

# Trust
Get-ADTrust -Filter *; Get-ADTrust -Identity domain.local
Get-ADForest; (Get-ADForest).Domains

# AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

## RID Cycling (No Creds Required)

```ps1
# NetExec
netexec smb 10.10.10.10 -u guest -p '' --rid-brute 10000

# Impacket
lookupsid.py -no-pass 'guest@dc.domain.local' 20000
lookupsid.py domain/user:pass@10.10.10.10

# Get SID from name
rpcclient -U '' 10.10.10.10 -c "lookupnames administrator"
```

## User Hunting

```ps1
# Sessions on machines
nxc smb 10.10.10.0/24 -u admin -p pass --sessions
impacket-smbclient admin@10.10.10.10  # then: who

# Find DCs
nslookup -type=srv _ldap._tcp.dc._msdcs.domain.local
nltest /dclist:domain.local
echo %LOGONSERVER%
$Env:LOGONSERVER
nmap -sV -sC 10.10.10.10  # check clock-skew in output
```

## LDAP Enumeration

```ps1
# ldapsearch
ldapsearch -x -H ldap://10.10.10.10 -b "DC=domain,DC=local" -D "user@domain.local" -W "(objectClass=user)" cn,sAMAccountName

# ldapdomaindump
ldapdomaindump -u 'domain\user' -p 'pass' 10.10.10.10 -o ~/dump/

# bloodyAD
bloodyAD --host 10.10.10.10 -d domain.local -u user -p pass get search --filter "(adminCount=1)" --attr sAMAccountName
bloodyAD --host 10.10.10.10 -d domain.local -u user -p pass get writable --otype USER --right WRITE
```

## AdminCount Users

```ps1
netexec ldap 10.10.10.10 -u user -p pass --admin-count
bloodyAD --host 10.10.10.10 -d domain.local -u user -p pass get search --filter "(admincount=1)" --attr sAMAccountName
Get-ADUser -LDAPFilter "(objectcategory=person)(samaccountname=*)(admincount=1)"
([adsisearcher]"(AdminCount=1)").findall()
```
