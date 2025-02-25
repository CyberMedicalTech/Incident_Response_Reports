# 🛡️ Understandign the Cyber Kill Chain Framework

## 📝 Summary
This post explains the **Cyber Kill Chain** Framework, detailing how threat actors progress through different attack stages and how SOC teams can detect and stop them.

## 🔥 Cyber Kill Chain Breakdown
The Cyber Kill Chain consits of seven sequential steps an attacker mustc complete to carry out a successful attack. Dirupting any step can prevent the attack from succeeding.

### 1. Reconnaissance
- Attackers gather information about the target organization.
  - Passive: Use of indirect methods to gather information from public sources.
    - Google, job listings, company websites.
  - Active: Some level of interaction with the target. Attacker will probe your system to look for open ports and services
      - Port scanning, NMAP, vulerability scanners.
- Methods: Open-Sourch Intelligence (OSINT), social engineering, scanning for vulerabliities.
- Goal of attacker: Find a weakness that can be exploited.
  
### 2. Weaponization
- Creating a payload or exploit to use against the target after weaknees is identified during Reconnaissance phase.
-   - Metasploit or Exploit-DB: Repositories for known exploits.
    - Veil Framework: Used to generate evasion code for malware.
    - Social Engineering Toolkit.
- Examples: Malware creation, exploit development, malicious document crafting.
- Goal of attacker: Select weapon(s) based on earlier Recon.

### 3. Delivery
- Selecting which weapon to deliver to the exloit of the target system.
    - Website: Attackers can infect a website your users frequent.
    - User Input: Attacker has some interaction.
    - Email: Malware emmbedded into email forms.
- Methods: Phising emails, infected USB devices, drive-by downloads.

### 4. Exploitation
- The attacker has accomplished executing the malicious weapon to gain access.
  - The exloit could come as: Buffer Overflow. SQL Injection. Malware. Javascript Hijack.
- Possible protections after attacker gains access:
    - Protection:
      - Data Execution Prevention (DEP): Software and Hardware feature that tries to locate code in memory located where it should not be, and attempts to prevent it from executing.
      - Anti-Exploit: Last line of defense that is monitoring for unusual calls to memory.
    - Detection
  -  Once at this stage you are trying to detect exploits that have already been executed.
      - Sandbox:
- Examples: Exploiting software vulnerabilities, running malicious scripts.
-Goal of attacker: To gain better access.

### 5. Installation.
- Establishing a successful exploitation gives a better level access to do harm to the target enviornment. This can allow the attacker to take control at any point in the future.
- Limited protective measures can be useful when an attacker has gotten this far.
  - Protect:
      - Linux: CHROOT can be used as a way to isolate processes from the rest of the system which will limit what the attacker has access to.
      - Windows: can disable powershell altogether.
  - Detect: tools used post infection to monitor files and activity.
      - User Behaviour Analysis (UBA) /EDR: Flags new/unauthorized programs that have been installed and detects changes to systems and registries. This should cause a log or alert to be detected in the Response stage.
- Respond:
    - Follow incident response SOPS
    - Identify device, isolate, wipe.
  - Recover: Restore or reimage system to a known good state.
- Examples: Installing backdoors, creating persistence mechanisms.
- Goal of attacker: Gain persistant access.

### 6. Command & Control (C2)
- The system is completely compromised and the attacker establishes remote control.
  -  Defense from this point is limiting what the attacker can control and detecting activity.
      -  Network Segmentation: Makes it harder for attacker to move laterally and easier to detect using audit logs.
      -  Micro Segmentation: Leaves infected user completely isolated on a portal until further action can be taken.
      -  Next Genertation Firewalls C&C blocking: Blocks servers from known bad actors.
      -  DNS Redirect
      -  Application Control: Layer 7 of TCP/IP that is used to block known remote access tools like telnet, SSH, powershell.
      -  SSL Deep Packet Inspection.
      -  IOC ?? Read more
    
- Examples: C2 servers, re,pte administration tools, encrypted communication.

### 7. Action on Objective
- The attacker completes their desired action.
- Zero Trust Security is built around this phase. Trust no one by default until you can prove otherwise.
  -  Detects infected machines and limits the amount of damage that can be done.
- Goal of attacker: Data exfiltration, system disruption, privilege escalation, lateral movement.

## How to Break the Chain
Organizations must analyze each phase and implement countermeasures:
- **Reconnaissance:** Monitor and block suspicious scanning activity. Limit public information. Disable unused ports/services. Implement honeypots against would be attackers. IPS.
- **Weaponization:** Deploy endpoint protection and malware sandboxing. Patch management. Disable Office Macros. Antivirus. IPS. Audit Logging. MFA.
- **Delivery:** Implement email security, user training, and web filtering (prevent user from visiting known questionable sites) DNS Filtering. SSL inspections to be aware of what is passing through ecrypted tunnels. Phising campaigns. DKIM uses signitures to verify email authenticity/ SPF makes sure email is coming from an authorized IP of domain.
- **Exploitation:** Keep systems patched and enforce least privilege.
- **Installation:** Use EDR (Endpoint Detection & Response) to detect persistence. DLL Hijacking. Remote Access Tools (RAT). Meterpreter (read more about this). Powershell commands.
- **Command & Control:** Block known C2 traffic using threat intelligence.
- **Action on Objective:** Implement data encryption and access controls. Data Leakage Prevention (DLP)

## Organizational Perspective
By understanding each phase of the Cyber Kill Chain, organizations can disrupt attacks early and strengthen their security posture.

## References
- Lockheed Martin Cyber Kill Chain Framework
