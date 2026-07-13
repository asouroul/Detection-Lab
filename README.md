# Detection Lab and Active Directory From Scratch

Building, Attacking and Detecting all in one.

Active Directory (AD) built from scratch, hardened audit policy, and a Splunk pipeline. Red hat for attacking the AD and Blue hat for catching myself doing it in Splunk.

## Tools used: 
- **VMware Workstation** for Virtualization
- **Windows Server 2022** for building the Active Directory
- **Ubuntu** for hosting the SIEM
- **Splunk** as the SIEM
- **Kali Linux** as the attacking machine with NetExec

## Why

Most orgs run on AD, and most detection logic is built around it. I wanted to build the actual identity infrastructure, attack it, and see if the audit policy and SIEM pipeline I configured would actually catch me.

---

## Architecture

| Role | OS | IP |
|---|---|---|
| Domain Controller | Windows Server 2022 | `192.168.174.131` |
| SIEM | Ubuntu 22.04 / Splunk Enterprise 9.3.0 | `192.168.174.129` |
| Attacker | Kali Linux | `192.168.174.128` |

Required to be in the same subnet so they can communicate.

Subnet mask: 255.255.255.0/24

---

## 1. Domain Controller Setup

Installed AD DS, promoted the server to a Domain Controller(DC) for a new forest named `corp.local`.

**!** **Issue:** server was on DHCP. A DC needs a stable, self-consistent IP/DNS — clients rely on SRV records to locate domain services, so an unstable DC IP breaks auth and replication.

**Fix:** static IP (`192.168.174.131`), DNS pointed to loopback (`127.0.0.1`).

<img width="458" height="301" alt="image" src="https://github.com/user-attachments/assets/7119d24b-9724-40de-b07e-7c999c274a67" />

---

## 2. User Population

PowerShell script to bulk-create 15 user accounts. Verified in Active Directory Users and Computers.

<img width="960" height="416" alt="image" src="https://github.com/user-attachments/assets/48800e15-1e02-49ce-b2d7-439f360009ee" />

<img width="382" height="600" alt="image" src="https://github.com/user-attachments/assets/44941205-c843-4384-9429-d9bb66cc4d4e" />


---

## 3. Audit Policy

Default audit policy doesn't log what's needed for detection. Modified Default Domain Policy (`gpmc.msc`) → Advanced Audit Policy Configuration:

- **Audit Logon** (Success/Failure) → Event IDs `4624` / `4625`
- **Audit User Account Management** (Success/Failure) → Event ID `4724`

---

## 4. SIEM Pipeline

- Installed Splunk Enterprise 9.3.0 on Ubuntu (`wget` / `dpkg`).
- **!** **Issue:** disk space error (`diskspace breached the red threshold`) on first launch.
- **Fix:** grew root partition via LVM (`resize2fs`), restarted Splunk.
- Configured indexer to receive on port `9997`.
<img width="1637" height="220" alt="image" src="https://github.com/user-attachments/assets/953e242e-1705-4b4c-85fa-cff1789df9ce" />

- Installed Splunk Universal Forwarder on the DC (`Invoke-WebRequest`).
**Splunk Search showing the Windows host checking in**
<img width="596" height="274" alt="image" src="https://github.com/user-attachments/assets/53aa0a6a-f3aa-4cb3-a88f-c99785dbd19e" />

- `inputs.conf` to monitor `WinEventLog://Security`, forward to SIEM.
**Powershell**
```
$confPath = "C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf"
$confContent = @"
[WinEventLog://Security]
disabled = 0
index = main
"@
Set-Content -Path $confPath -Value $confContent
Restart-Service SplunkForwarder
```
**Splunk Search showing `source="WinEventLog:Security"**
<img width="1655" height="770" alt="image" src="https://github.com/user-attachments/assets/561e9c61-c57d-4682-a345-aa8c7e21f659" />

---

## 5. Attacking My Own Build

Set `billy`'s password to `Admin123!` (weak, guessable).

**Attack (Kali):**
```bash
nxc smb 192.168.174.131 -u users.txt -p 'Admin123!' --continue-on-success
```
Result: 14 failed logons, 1 compromise (`billy`).

<img width="922" height="315" alt="image" src="https://github.com/user-attachments/assets/bfae0643-fb97-4870-a558-fa05d63b2dd1" />

**Caught it in Splunk:** Windows Security events don't cleanly expose target user / source IP through default field extraction for this event type — wrote a custom SPL query with regex extraction. Pipeline surfaced the exact attack I'd just run:
```
index="main" source="WinEventLog:Security" (EventCode="4625" OR EventCode="4624") "Logon Type: 3" | 
rex field=_raw "Account Name:\s+(?<TargetUser>[a-zA-Z0-9]+)" 
| rex field=_raw "Source Network Address:\s+(?<AttackerIP>[0-9\.]+)" 
| eval Status=if(EventCode=="4624", "Successful Compromise", "Failed Logon") 
| stats count by TargetUser, Status, AttackerIP 
| sort - Status
```
<img width="1079" height="66" alt="image" src="https://github.com/user-attachments/assets/2b0fbd5b-37a2-4690-9a11-ae2838640f1c" />


#### Filter Command
```
index="main" source="WinEventLog:Security" EventCode=4625
```

- 14× Event ID 4625 (failed), same source IP
<img width="428" height="207" alt="image" src="https://github.com/user-attachments/assets/1b9af238-c837-4cab-84b5-dca5f91eefc8" />
<img width="1104" height="634" alt="image" src="https://github.com/user-attachments/assets/40440bf9-08b5-4273-a591-96a5900dce5d" />

#### Filter Command
```
index="main" source="WinEventLog:Security" EventCode=4624 Logon_Type=3
```

- 1× Event ID 4624 (success) → `billy`, same source IP
<img width="666" height="517" alt="image" src="https://github.com/user-attachments/assets/7659aa47-c554-4086-85a4-624f81467d37" />



## 6. Incident Response
**Remediation:** reset `billy`'s password. Verified in Splunk:
```
Set-ADAccountPassword -Identity "billy" -NewPassword (ConvertTo-SecureString "Quarantine2026!" -AsPlainText -Force) -Reset:$true
```

```
index="main" source="WinEventLog:Security" EventCode=4724
```
<img width="783" height="541" alt="image" src="https://github.com/user-attachments/assets/f5e2d2f1-af8b-4c0f-86b6-df4d7a407b99" />

- **Subject Account Name:** The administrator (me) who issued the command.
    
- **Target Account Name:** The compromised user (`billy`).

---

## What I Learned

- DHCP on a DC breaks DNS/replication — the wizard succeeds, the domain doesn't work right.
- Default audit policy logs almost nothing useful for detection; has to be explicitly enabled via GPO.
- GPO pushes config domain-wide instead of per-machine — the realistic approach past a single server.
- Windows Security event fields aren't analyst-ready out of the box; needed manual regex extraction in Splunk.
- The attack was worth running specifically because it forced the whole chain (audit policy → forwarder → SIEM → query) to prove itself against real traffic — a config review alone wouldn't have caught the field-extraction issue.

---

## Next Steps

- Second DC — replication, FSMO roles.
- Proper OU structure with per-OU GPOs instead of one flat Default Domain Policy.
- Tiered admin model (Tier 0/1/2), delegated permissions instead of blanket Domain Admin.
- LAPS for local admin password management.
- Automate the build (Terraform/Vagrant + PowerShell DSC).
- Convert the SPL search into a scheduled correlation alert.
- Add a smart-lockout/fine-grained password policy, re-run the spray, compare detection vs. prevention.

---

MITRE ATT&CK: T1110.003 (Password Spraying) — Credential Access

---

## Appendix

```bash
# Disk fix
sudo resize2fs /dev/sda2
```
