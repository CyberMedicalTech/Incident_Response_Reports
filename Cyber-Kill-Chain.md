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
- Goal: Find a weakness that can be exploited.
  
### 2. Weaponization
- Creating a payload or exploit to use against the target after weaknees is identified during Reconnaissance phase.
-   - Metasploit or Exploit-DB: Repositories for known exploits.
    - Veil Framework: Used to generate evasion code for malware.
    - Social Engineering Toolkit.
- Examples: Malware creation, exploit development, malicious document crafting.
- Goal: Select weapon(s) based on earlier Recon.

### 3. Delivery
- Selecting which weapon to deliver to the exloit of the target system.
    - Website: Attackers can infect a website your users frequent.
    - User Input: Attacker has some interaction.
    - Email: Malware emmbedded into email forms.
- Methods: Phising emails, infected USB devices, drive-by downloads.

### 4. Exploitation
- The attacker has accomplished executing the malicious weapon to gain access.
- Examples: Exploiting software vulnerabilities, running malicious scripts.

### 5. Installation.
- Establishing a foothold in the target enviornment.
- Examples: Installing backdoors, creating persistence mechanisms.

### 6. Command & Control (C2)
- The attacker establishes remote control over the compromised system.
- Examples: C2 servers, re,pte administration tools, encrypted communication.

### 7. Action on Objective
- The attacker completes their goal.
- Goals: Data exfiltration, system disruption, privilege escalation.

## How to Break the Chain
Organizations must analyze each phase and implement countermeasures:
- **Reconnaissance:** Monitor and block suspicious scanning activity. Limit public information. Disable unused ports/services. Implement honeypots against would be attackers. IPS.
- **Weaponization:** Deploy endpoint protection and malware sandboxing. Patch management. Disable Office Macros. Antivirus. IPS. Audit Logging. MFA.
- **Delivery:** Implement email security, user training, and web filtering (prevent user from visiting known questionable sites) DNS Filtering. SSL inspections. Phising campaigns. DKIM uses signitures to verify email authenticity/ SPF makes sure email is coming from an authorized IP of domain.
- **Exploitation:** Keep systems patched and enforce least privilege.
- **Installation:** Use EDR (Endpoint Detection & Response) to detect persistence.
- **Command & Control:** Block known C2 traffic using threat intelligence.
- **Action on Objective:** Implement data encryption and access controls.

## Organizational Perspective
By understanding each phase of the Cyber Kill Chain, organizations can disrupt attacks early and strengthen their security posture.

## References
- Lockheed Martin Cyber Kill Chain Framework
