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
- The program will find the vulnerable service
- Modify its configuration to point to a malicious payload
- Trigger the service to execute the payload as SYSTEM
- A new SYSTEM command prompt will appear
- Type `whoami` to see "nt authority\system"

## What Actually Happens

When you run the exploit as a standard user:

1. **Reconnaissance** - Finds the vulnerable service with weak permissions
2. **Exploitation** - Modifies the service binary path to point to a malicious payload
3. **Execution** - Starts the service, triggering execution as SYSTEM
4. **Proof** - Creates `C:\SYSTEM_PRIVESC_PROOF.txt` containing output from `whoami` and system info

The proof file demonstrates that arbitrary code was executed with SYSTEM privileges, showing:
- Current user (nt authority\system)
- Timestamp of execution
- Hostname
- Network information

This is exactly how real privilege escalation attacks work - from standard user to complete system control.

## Files

- **privesc_demo.c** - The main exploit (run as standard user)
- **setup_vulnerable_service.c** - Creates the vulnerable environment (run as admin)
- **cleanup.c** - Removes the vulnerable service (run as admin if needed)

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
