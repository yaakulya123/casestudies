# Ethical Hacking Test Cases & Case Studies

> ⚠️ **Disclaimer**
> These exercises are for **educational and ethical purposes only** and must be run **only in an isolated lab** you control. Never target real networks/systems. Obtain written permission for any testing. Avoid using live malware—prefer benign, simulated payloads.

---

## Lab Prerequisites

* Host machine with **VirtualBox** or **VMware Workstation/Player**
* Two+ VMs (snapshots enabled) and an **internal-only** virtual network
* Basic familiarity with Linux/Windows CLI, networking (IP, ports, SMB), and log collection
* Optional: a separate **IDS VM** (Snort/Suricata)

> **Safety tips**
>
> * Take **snapshots** before each exercise and revert after.
> * Disable host-only file sharing and clipboard between VMs during offensive phases.
> * Use **benign simulation payloads** or prebuilt lab samples; do **not** deploy real ransomware.

---

## Case Study 1: Simulating a WannaCry‑style Ransomware Scenario

![Case Study 1 – WannaCry Simulation](https://github.com/user-attachments/assets/21bab4e5-79ae-4d9f-840d-53f808b94164)

**Objective:** Observe pre‑patch Windows SMB exploitation behavior and practice detection/response procedures akin to WannaCry (MS17‑010 / CVE‑2017‑0144) **using safe simulations**.

### Environment

* **Windows 7** VM (intentionally unpatched for MS17‑010 in the lab)
* **Kali Linux** (attacker)
* Both on an **internal/NAT‑only** network with no internet egress

### Tools

* **Metasploit Framework** (for **simulated** EternalBlue exploitation workflow)
* **Wireshark** (to inspect SMB traffic)
* **Sysinternals**: Process Explorer, Autoruns, TCPView (host triage)
* Optional: a **benign ransomware simulator** or a script that creates ransom‑note‑like files (non‑encrypting) to demonstrate impact safely

### Tasks (high‑level, lab‑safe)

1. **Enumeration:** From Kali, identify the Windows host and open SMB (port 445). Capture traffic in Wireshark (`tcp.port == 445`).
2. **Exploit Simulation:** In Metasploit, load the MS17‑010 workflow **per vendor docs** and execute **against the lab Windows VM only**. Use a **non‑destructive payload** (e.g., command execution that writes a file). Document pre‑conditions (unpatched OS, SMB enabled).
3. **Impact Simulation:** Deploy a benign script on Windows that:

   * Creates a directory of test files,
   * Renames/duplicates some files,
   * Drops a **ransom‑style note** (plain text) to simulate user impact.
     *Do not encrypt or exfiltrate data.*

**Deliverables:** Network capture (pcap), host triage screenshots, IOC list, and a one‑page mitigation plan.

---

## Case Study 2: Steganography – Hiding & Detecting Data in Images

![Case Study 2 – Steganography Demonstration](https://github.com/user-attachments/assets/de606659-e03d-46a0-8889-79f517c76353)


**Objective:** Demonstrate data hiding in images and apply steganalysis to detect covert channels.

### Environment

* Windows or Linux workstation
* Offline folder of lab images (e.g., `.jpg`)

### Tools

* **steghide** or Python **stegano**
* **HxD** (hex editor) or `xxd`
* **zsteg** and/or **stegseek** for detection/recovery attempts

### Tasks

1. **Embed (benign) data** (e.g., a small TXT) into an image using `steghide` or `stegano`. Keep the original and the modified image.
2. **Open normally** to show the picture is visually identical.
3. **Extract** the hidden data with the correct passphrase.
4. **Detect/Analyze**:

   * Run `zsteg`/`stegseek` on both images; compare entropy/heuristic outputs.
   * Inspect file headers and trailing data in a hex editor.
5. **Report:** Document which methods detected hiding, false positives, and operational guidance for SOCs.

**Deliverables:** Commands used, detection tool outputs, and a short write‑up on **strengths/limits** of each tool.

---

## Case Study 3: Static & Dynamic Malware Analysis (Lab‑Safe Samples)

![Case Study 3 – Malware Analysis Workflow](https://github.com/user-attachments/assets/494ac7de-f07f-4ca1-8133-5e9a3758b591)

**Objective:** Perform first‑pass analysis of a **benign or pre‑sanitized sample** using static and sandboxed dynamic techniques.

### Environment

* **Windows 10** sandbox VM (isolated, no shared clipboard/drives)
* **REMnux** VM for tooling and network monitoring

### Tools

* **Static:** `strings`, Detect It Easy (DIE), PEiD, hashes (SHA‑256), VirusTotal (hash lookups)
* **Dynamic:** Procmon, RegShot, Wireshark, **Cuckoo Sandbox** (or another contained sandbox)

### Tasks

1. **Static triage:** Compute hashes, run `strings`, use DIE/PEiD to assess packers and imports; hypothesize behavior.
2. **Baseline & Snapshot:** Take a RegShot baseline and VM snapshot.
3. **Dynamic run (sandboxed):** Execute the sample inside Cuckoo or the Windows VM with Procmon + Wireshark capturing. Limit runtime (e.g., 2–5 minutes). Revert snapshot after.
4. **Compare state:** RegShot diff; list file/registry modifications and network IOCs (domains/IPs, URIs).
5. **Reporting:** Build a one‑page **IOC sheet** and short **defensive recommendations** (EDR rules, blocklists, YARA opportunities).

**Deliverables:** Hashes, strings of interest, sandbox report, packet capture, and IOC table.

---

## Case Study 4: Threat Intelligence – APT TTP Mapping with MITRE ATT\&CK

![Case Study 4 – ATT\&CK Navigator Mapping](https://github.com/user-attachments/assets/fa9f24ff-de8b-46b3-a3cc-345f4cfe79e8)

**Objective:** Research a real APT (e.g., **APT28** or **Lazarus**) and map its **TTPs** to ATT\&CK, then propose detections.

### Environment

* Any OS with web access
* MITRE **ATT\&CK Navigator** (web)

### Tools

* **ATT\&CK** & Navigator, vendor reports, VirusTotal (hash lookups), optional **Maltego**, **OpenCTI**, or **MISP** for intel enrichment

### Tasks

1. **Intel Collection:** Gather recent public reports on the chosen APT; extract initial access, execution, persistence, C2, and exfiltration methods.
2. **Mapping:** Create a layer in ATT\&CK Navigator highlighting relevant **tactics/techniques**. Attach notes and references to each technique.
3. **Detections/Mitigations:** For each high‑value technique, propose host/network detections (e.g., event IDs, Sigma/EDR rules), prevention (hardening, policy), and response playbook steps.
4. **Presentation:** Export the ATT\&CK layer (JSON) and a 5‑slide summary of findings.

**Deliverables:** ATT\&CK Navigator layer file, technique notes with sources, and a detection/mitigation matrix.

---

## Case Study 5: Network IDS Hands‑On (Snort/Suricata)

![Case Study 5 – Snort/Suricata IDS](https://github.com/user-attachments/assets/d1cf427d-25df-4aab-9f80-c7c377c3ea10)

**Objective:** Generate benign attack‑like traffic, write a simple detection rule, and validate alerts end‑to‑end.

### Environment

* **Kali** (traffic generator)
* **Victim** VM (Windows or Linux)
* **IDS** VM (Snort or Suricata) inline/tap on the same lab network

### Tools

* **Snort** or **Suricata**
* **Wireshark**
* **Nmap** or Metasploit (to create benign scan traffic)

### Tasks

1. **Traffic Generation:** From Kali, run a **limited** SYN scan against the victim (few ports) only inside the lab. Capture traffic on the IDS.
2. **Rule Authoring:** Add a minimal custom rule to detect the scan pattern (e.g., SYNs to SMB port). Keep it generic and non‑disruptive.
3. **Validation:** Re‑run the scan and confirm alerts in the IDS console/logs. Compare with Wireshark pcap.
4. **Tuning:** Reduce false positives by narrowing the rule (destination IP, thresholds) and document changes.

**Deliverables:** IDS rule snippet, alert screenshots/log lines, and a tuning rationale.

---

## Rubric (Suggested)

* **Method & Safety (25%)** – Follow lab isolation, snapshots, and non‑destructive payload policy
* **Rigor (25%)** – Clear steps, repeatable evidence (pcaps, logs, screenshots)
* **Analysis (30%)** – Accurate IOCs, ATT\&CK mapping, detection logic quality
* **Communication (20%)** – Concise reporting with references and remediation

---

## References (authoritative docs & tools)

* **MS17‑010 / CVE‑2017‑0144** (Microsoft MSRC): [https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-0144)
* **Metasploit Framework Docs**: [https://docs.metasploit.com/](https://docs.metasploit.com/)
* **Wireshark**: [https://www.wireshark.org/](https://www.wireshark.org/)
* **Microsoft Sysinternals**: [https://learn.microsoft.com/en-us/sysinternals/](https://learn.microsoft.com/en-us/sysinternals/)
* **steghide**: [https://steghide.sourceforge.net/](https://steghide.sourceforge.net/)
* **zsteg**: [https://github.com/zed-0xff/zsteg](https://github.com/zed-0xff/zsteg)
* **stegseek**: [https://github.com/RickdeJager/stegseek](https://github.com/RickdeJager/stegseek)
* **REMnux**: [https://remnux.org/](https://remnux.org/)
* **Cuckoo Sandbox**: [https://cuckoosandbox.org/](https://cuckoosandbox.org/)
* **VirusTotal**: [https://www.virustotal.com/](https://www.virustotal.com/)
* **Detect It Easy (DIE)**: [https://github.com/horsicq/DIE-engine](https://github.com/horsicq/DIE-engine)
* **RegShot**: [https://sourceforge.net/projects/regshot/](https://sourceforge.net/projects/regshot/)
* **MITRE ATT\&CK**: [https://attack.mitre.org/](https://attack.mitre.org/)
* **ATT\&CK Navigator**: [https://mitre-attack.github.io/attack-navigator/](https://mitre-attack.github.io/attack-navigator/)
* **Maltego**: [https://www.maltego.com/](https://www.maltego.com/)
* **OpenCTI**: [https://www.opencti.io/en/](https://www.opencti.io/en/)
* **MISP**: [https://www.misp-project.org/](https://www.misp-project.org/)
* **Snort**: [https://www.snort.org/](https://www.snort.org/)
* **Suricata**: [https://suricata.io/](https://suricata.io/)
* **Nmap**: [https://nmap.org/](https://nmap.org/)

---

### Notes on Ethical Boundaries

This guide intentionally avoids step‑by‑step weaponization details. It focuses on **offensive and defensive education**, safe simulation, and measurable detection/response skills. Where exploitation tooling is referenced, use only vendor documentation and **lab‑safe, non‑destructive payloads**.
