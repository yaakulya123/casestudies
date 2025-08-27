# Ethical Hacking Test Cases & Case Studies

> ⚠️ **Disclaimer**  
> These exercises are for **educational and ethical purposes only**.  
> They must be conducted in a **controlled lab environment**, never on production systems.  
> Always obtain proper permission before testing systems.

---

## Case Study 1: Simulating a WannaCry-style Ransomware Attack

**Objective:** Understand how ransomware spreads, encrypts files, and how to detect and mitigate it.

### Environment
- Windows 7 VM (vulnerable system – no patches)  
- Kali Linux VM (attacker machine)  
- Both connected via VirtualBox/VMware internal NAT network  

### Tools Required
- Metasploit Framework (for EternalBlue exploit simulation)  
- Wireshark (to capture malicious traffic)  
- Sysinternals Suite (for Windows forensic observation)  
- [Optional] WannaCry ransomware sample (safe dummy versions for labs, e.g., Metasploitable payloads)  

### Tasks
1. Simulate exploitation using EternalBlue (`ms17_010_eternalblue` in Metasploit).  
2. Demonstrate file encryption and ransom note (safe simulation).  
3. Analyze attack behavior with Wireshark.  
4. Discuss mitigation: patching (MS17-010), backups, IDS signatures.  

**Learning Outcome:** Students learn exploitation vectors, ransomware behavior, and defensive measures.  

---

## Case Study 2: Steganography Attack with Image Injection

**Objective:** Demonstrate how attackers hide payloads inside images and how to detect them.  

### Environment
- Windows/Linux system  
- Offline lab with test images  

### Tools Required
- `steghide` or `stegano` (Python)  
- Hex editor (HxD)  
- StegExpose (detection tool)  

### Tasks
1. Take a normal image (e.g., `.jpg`).  
2. Inject a text file or malware sample into the image.  
3. Show the image still opens normally.  
4. Extract hidden payload with steghide.  
5. Detect anomalies using StegExpose.  

**Learning Outcome:** Students understand covert data exfiltration and steganalysis.  

---

## Case Study 3: Static & Dynamic Malware Analysis

**Objective:** Learn safe methods to analyze malware behavior.  

### Environment
- Windows 10 sandbox VM  
- REMnux Linux VM (malware analysis distro)  

### Tools Required
- **Static Analysis:** PEiD, Detect It Easy (DIE), strings, VirusTotal API  
- **Dynamic Analysis:** Procmon, RegShot, Wireshark, Cuckoo Sandbox  

### Tasks
1. Perform static analysis (headers, imports, strings).  
2. Run malware inside Cuckoo Sandbox.  
3. Monitor registry, file system, and network changes.  
4. Collect Indicators of Compromise (IOCs).  

**Learning Outcome:** Students gain malware reverse-engineering basics.  

---

## Case Study 4: Threat Intelligence & APT Mapping

**Objective:** Map real-world APT campaigns to MITRE ATT&CK framework.  

### Environment
- Any OS (Linux preferred)  
- Online access to MITRE ATT&CK navigator  

### Tools Required
- MITRE ATT&CK Navigator  
- VirusTotal / Maltego (optional enrichment)  
- OpenCTI or MISP (if available)  

### Tasks
1. Select a known APT group (e.g., Lazarus, APT28).  
2. Research their attack patterns and tools.  
3. Map techniques to MITRE ATT&CK.  
4. Propose defenses against those techniques.  

**Learning Outcome:** Students learn cyber threat intelligence mapping and defensive alignment.  

---

## Case Study 5: Network Intrusion Detection with Snort/Suricata

**Objective:** Learn how IDS detects and blocks malicious traffic.  

### Environment
- Kali Linux (attacker)  
- Windows/Linux (victim)  
- Snort/Suricata box (IDS)  

### Tools Required
- Snort or Suricata IDS  
- Wireshark  
- Metasploit/Nmap (to generate malicious traffic)  

### Tasks
1. Perform scanning/brute force with Kali.  
2. Capture traffic using Snort.  
3. Create a custom Snort rule to detect Nmap scans.  
4. Validate if IDS detects/logs/block traffic.  

**Learning Outcome:** Students gain blue team detection engineering skills.  

---

# Final Notes
- Always run in **isolated virtual labs**.  
- Encourage students to **document findings** with screenshots and IOCs.  
- Difficulty can be scaled with **timed challenges or red-vs-blue exercises**.  
