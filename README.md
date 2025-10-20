# Windows Privilege Escalation Educational Demo

## Purpose
This program demonstrates a **real working privilege escalation** from standard user to NT AUTHORITY\SYSTEM through service misconfiguration exploitation.

## Learning Objectives
Students will understand:
1. How Windows services and permissions work
2. Service misconfiguration vulnerabilities (SERVICE_CHANGE_CONFIG)
3. Privilege escalation from User -> SYSTEM
4. Real-world attack techniques used by penetration testers
5. Detection and mitigation strategies

## Quick Start

### Step 1: Setup (Run as Administrator)
```bash
# Compile the setup tool
gcc setup_vulnerable_service.c -o setup_vulnerable_service.exe

# Run it as admin to create the vulnerable service
setup_vulnerable_service.exe
```

### Step 2: Exploit (Run as Standard User)
```bash
# Compile the exploit
gcc privesc_demo.c -o privesc_demo.exe

# Open a STANDARD (non-admin) command prompt
# Run the exploit
privesc_demo.exe
```

### Step 3: Watch the Magic
- The program identifies the vulnerable service (VulnDemoService)
- Creates a batch file payload (payload.bat) that runs PowerShell commands
- Modifies the service's binary path to point to the payload
- Starts the service to trigger payload execution as SYSTEM
- Creates a proof file at C:\SYSTEM_PRIVESC_PROOF.txt with SYSTEM user info

## What Actually Happens

When you run the exploit as a standard user:

1. **Reconnaissance Phase**
   - Displays current username and privilege level (Standard User)
   - Identifies VulnDemoService as the target
   - Verifies SERVICE_CHANGE_CONFIG permissions are available

2. **Payload Creation**
   - Creates `payload.bat` in the current directory
   - Batch file executes this PowerShell command:
     ```powershell
     $info = whoami
     $info | Out-File -FilePath 'C:\SYSTEM_PRIVESC_PROOF.txt' -Encoding ASCII
     'SYSTEM privilege escalation successful!' | Out-File -FilePath 'C:\SYSTEM_PRIVESC_PROOF.txt' -Append
     'Timestamp: ' + (Get-Date) | Out-File -FilePath 'C:\SYSTEM_PRIVESC_PROOF.txt' -Append
     'Hostname: ' + (hostname) | Out-File -FilePath 'C:\SYSTEM_PRIVESC_PROOF.txt' -Append
     ```
   - This proves SYSTEM access by writing `whoami` output with timestamp and hostname

3. **Service Modification**
   - Opens the vulnerable service with modification rights
   - Changes the service binary path to: `cmd.exe /c "payload.bat"`
   - This reconfigures what executable runs when the service starts

4. **Trigger Execution**
   - Starts the service, causing Windows to execute the modified binary path
   - Service runs as NT AUTHORITY\SYSTEM, so payload executes with SYSTEM privileges
   - Service errors are expected (it's not a real service executable)

5. **Proof of Exploitation**
   - Creates `C:\SYSTEM_PRIVESC_PROOF.txt` containing:
     - "nt authority\system" (proving SYSTEM execution)
     - Success message
     - Timestamp
     - Hostname
   - Displays educational information about the attack

This demonstrates exactly how real privilege escalation attacks work - from standard user to complete system control in seconds.

## Files

- **privesc_demo.c** - The main exploit that demonstrates privilege escalation (run as standard user)
- **setup_vulnerable_service.c** - Creates VulnDemoService with weak permissions (run as admin)
- **cleanup.c** - Removes the vulnerable service and cleans up (run as admin)

**Generated during execution:**
- **payload.bat** - Batch file payload created by privesc_demo.c
- **vuln_service.exe** - Dummy service executable created by setup_vulnerable_service.c
- **C:\SYSTEM_PRIVESC_PROOF.txt** - Proof file demonstrating SYSTEM execution

## Key Teaching Points

### Why This Matters
- Many real-world systems have similar misconfigurations
- Ransomware needs SYSTEM to encrypt everything
- Backdoors need SYSTEM to survive reboots
- Data exfiltration needs SYSTEM to access protected files

### Defense Strategy
- **Principle of Least Privilege** - Services should run as low-privilege accounts
- **Regular Audits** - Check service permissions quarterly
- **Monitoring** - Alert on service configuration changes
- **Patching** - Keep Windows and all services updated

### Detection Commands
```powershell
# Find services with weak permissions
accesschk.exe -uwcqv "Users" *

# Check service configuration
sc qc ServiceName

# Monitor service changes (Event Viewer)
# Event ID 7040 = Service startup type changed
```

## Additional Resources for Students

### Tools for Further Exploration:
- **PowerUp.ps1**: PowerShell script for privilege escalation enumeration
- **WinPEAS**: Windows Privilege Escalation Awesome Scripts
- **AccessChk**: Sysinternals tool for checking permissions
- **Procmon**: Process Monitor for observing system behavior

### Reading Material:
- Windows Internals (Book by Mark Russinovich)
- MITRE ATT&CK Privilege Escalation Techniques
- Microsoft Security Development Lifecycle (SDL)

## Safety and Ethics

**IMPORTANT**: This program is for authorized educational use only.

Remind apprentices:
- Only use in lab environments or with explicit permission
- Unauthorized privilege escalation is illegal
- Understanding attacks helps build better defenses
- Ethical security professionals respect boundaries

## Lab Exercise Ideas

1. **Detection Exercise**: Have students use Windows Event Viewer to identify when privilege escalation attempts occur

2. **Hardening Exercise**: Students configure a vulnerable service and then secure it properly

3. **Blue Team Exercise**: Students write PowerShell scripts to detect unquoted service paths

4. **Red Team Exercise**: In a controlled environment, students attempt privilege escalation and document findings

## Questions for Discussion

1. Why does Windows require explicit privilege enabling even for administrators?
2. What is the difference between administrator and SYSTEM privileges?
3. How can organizations detect privilege escalation attempts in real-time?
4. What role does UAC play in preventing these attacks?
5. How would you design a service to minimize privilege escalation risks?

## License
Educational use only. Use responsibly and ethically.
