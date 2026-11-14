import type { Module } from "@/lib/types";

export const modules: Module[] = [
  {
    slug: "timeline",
    title: "Timeline Reconstruction",
    subtitle: "Super-Timeline Analysis of a Compromised Windows Host",
    description:
      "Reconstruct a complete, timestamp-accurate picture of attacker " +
      "activity on a compromised Windows host. Covers forensic image " +
      "acquisition, artifact parsing (MFT, registry, event logs), " +
      "super-timeline generation with plaso, and correlation of logon, " +
      "execution, and persistence events — a complete host-timeline " +
      "workflow for Windows.",
    objective:
      "Build a chronological, evidence-backed timeline of the intrusion on " +
      "a Windows system — from initial access through persistence to " +
      "attacker actions — and use it to answer what happened, when, and in " +
      "what order.",
    context:
      "A Windows workstation or server is suspected to be compromised: " +
      "antivirus alerts, unusual outbound traffic, or user reports. You " +
      "have a forensic disk image and must reconstruct the sequence of " +
      "attacker activity without modifying the original evidence.",
    steps: [
      {
        order: 1,
        title: "Evidence Acquisition & Hashing",
        body:
          "Acquire (or receive) the forensic disk image and verify its " +
          "integrity before analysis: compute SHA256 hashes of the image " +
          "and every exported artefact, log chain-of-custody, and work only " +
          "from copies. Mount images read-only — never boot or mount the " +
          "original media writable.",
        tools: ["FTK Imager", "sha256sum", "dc3dd"],
      },
      {
        order: 2,
        title: "Artifact Extraction",
        body:
          "Parse the highest-value Windows artefacts: the $MFT for file " +
          "creation/modification timestamps, registry hives (SAM, SYSTEM, " +
          "SOFTWARE, NTUSER.DAT) for persistence and user activity, event " +
          "logs (Security, System, PowerShell) for logons and process " +
          "creation, plus prefetch and USN journal entries.",
        tools: ["MFTECmd", "RegRipper", "EvtxECmd"],
      },
      {
        order: 3,
        title: "Super-Timeline Generation",
        body:
          "Ingest parsed artefacts into plaso with log2timeline to build a " +
          "unified super-timeline across file system, registry, and event " +
          "logs. Filter noise (OS update churn, scheduled maintenance) with " +
          "psort queries and keyword searches to isolate the attack window.",
        tools: ["log2timeline", "psort", "Timeline Explorer"],
      },
      {
        order: 4,
        title: "Correlation & Reporting",
        body:
          "Correlate suspicious event sequences — e.g. 4624 logon → 4688 " +
          "process creation → 7045 service install → file drop in " +
          "user-writeable paths — to reconstruct attacker actions. Attribute " +
          "timestamps to accounts and hosts, flag anti-forensics gaps " +
          "(event ID 1102 log clears), and deliver the timeline with IOCs.",
        tools: ["Timeline Explorer", "grep", "awk"],
      },
    ],
    deliverables: [
      "Consolidated super-timeline of the intrusion, from initial access to impact",
      "Initial access vector with the first malicious timestamp",
      "Ordered sequence of attacker actions (logons, executions, persistence)",
      "Indicators of compromise (IPs, hashes, paths, mutexes) for detection engineering",
    ],
    tools: [
      "FTK Imager",
      "log2timeline",
      "plaso",
      "MFTECmd",
      "RegRipper",
      "sha256sum",
    ],
    icon: "Clock",
  },
  {
    slug: "memory",
    title: "Memory Forensics",
    subtitle: "Live-Analysis of a Compromised Host's RAM",
    description:
      "Analyze volatile memory from a compromised system to expose what " +
      "disk forensics cannot: injected code, fileless malware, active " +
      "network connections, and in-memory credentials. Covers memory " +
      "acquisition, image identification, process and network analysis, " +
      "code-injection detection, and IOC extraction.",
    objective:
      "Recover attacker activity from RAM that never touched disk — " +
      "malicious processes, injected code regions, active command-and-control " +
      "channels, and credentials — before the evidence evaporates.",
    context:
      "A host shows signs of an in-memory intrusion: suspicious processes, " +
      "beaconing traffic, or an EDR alert that vanished after reboot. You " +
      "have (or can take) a full physical memory capture of the running " +
      "system — the most volatile evidence available.",
    steps: [
      {
        order: 1,
        title: "Memory Acquisition & Integrity",
        body:
          "Capture RAM with a trusted acquisition tool (winpmem, FTK Imager, " +
          "or dumpit for Windows; LiME for Linux) to an external evidence " +
          "drive. Compute SHA256 of the capture immediately, record time of " +
          "acquisition and system time skew, and seal the original file.",
        tools: ["winpmem", "dumpit", "sha256sum"],
      },
      {
        order: 2,
        title: "Image Identification & Triage",
        body:
          "Identify the image profile before any analysis: OS family and " +
          "build (windows.info / imageinfo), kernel debugger block (KDBG), " +
          "and KPCR locations. Confirm the capture is complete and not " +
          "truncated — a bad image invalidates everything downstream.",
        tools: ["volatility3", "strings"],
      },
      {
        order: 3,
        title: "Process & Network Analysis",
        body:
          "Enumerate processes with pslist/pstree and cross-check with " +
          "psscan to find hidden or terminated processes. Review command " +
          "lines (cmdline), loaded DLLs (dlllist), and active network " +
          "endpoints (netscan) to spot beacons, reverse shells, and " +
          "mismatched parent-child relationships (e.g. Word spawning " +
          "powershell.exe).",
        tools: ["volatility3", "pslist", "netscan"],
      },
      {
        order: 4,
        title: "Code Injection & Malware Detection",
        body:
          "Hunt for injected code: malfind flags executable, unbacked memory " +
          "regions with RWX permissions; inspect VAD trees for anomalies; " +
          "dump suspicious regions and processes to disk, then scan them " +
          "with YARA rules and strings to identify packers, Cobalt Strike " +
          "beacons, and credential stealers.",
        tools: ["volatility3", "yara", "strings"],
      },
      {
        order: 5,
        title: "IOC Extraction & Reporting",
        body:
          "Consolidate findings into an IOC package: process names and PIDs, " +
          "command lines, network endpoints, injected-region hashes, and " +
          "recovered credentials. Hash every dumped artefact, map findings " +
          "to the attack timeline, and write the final report with " +
          "remediation guidance.",
        tools: ["sha256sum", "strings", "grep"],
      },
    ],
    deliverables: [
      "Identified malicious processes and their parent-child process tree",
      "Live network connections and C2 endpoints recovered from memory",
      "Hashes of injected code regions and dumped process images",
      "Recovered attacker command lines and in-memory payloads",
      "IOC package (hashes, IPs, domains, mutexes) for detection and hunting",
    ],
    tools: [
      "volatility3",
      "winpmem",
      "dumpit",
      "yara",
      "strings",
      "sha256sum",
      "grep",
    ],
    icon: "Cpu",
  },
  {
    slug: "network",
    title: "Network Traffic Analysis",
    subtitle: "PCAP Forensics of a Suspected Intrusion",
    description:
      "Dissect packet captures from a compromised network segment to " +
      "identify attacker infrastructure, reconstruct attacker activity, and " +
      "extract payloads. Covers PCAP validation, traffic baselining, stream " +
      "reconstruction, Zeek/Suricata hunting, and file carving with hashing " +
      "— a complete network forensics workflow.",
    objective:
      "Analyze a packet capture to identify malicious hosts, attacker " +
      "command-and-control infrastructure, exfiltrated data, and the " +
      "sequence of network activity during the intrusion.",
    context:
      "Your IDS/NSM flagged anomalous traffic — or a full-packet capture " +
      "was taken during an incident. You have a PCAP (or a directory of " +
      "PCAPs) spanning the incident window and must extract attacker " +
      "behavior, payloads, and indicators without modifying the capture.",
    steps: [
      {
        order: 1,
        title: "PCAP Scoping & Validation",
        body:
          "Profile the capture before diving in: capinfos reports packet " +
          "count, duration, link type, and average rate; verify the SHA256 " +
          "of the PCAP against the acquisition record; confirm interface " +
          "direction and timezone so every downstream timestamp is sound.",
        tools: ["capinfos", "sha256sum"],
      },
      {
        order: 2,
        title: "Traffic Baseline & Profiling",
        body:
          "Build a statistical picture: protocol hierarchy (tshark -z " +
          "io,phs), top talkers (endpoints), conversation matrix, and DNS/HTTP " +
          "query volumes. Flag anomalies — beacon-like periodicity, rare " +
          "ports, unusual ASNs — to scope the hunt.",
        tools: ["tshark", "tcpdump"],
      },
      {
        order: 3,
        title: "Stream Reconstruction",
        body:
          "Follow TCP/UDP streams in Wireshark (or tshark -q -z follow) to " +
          "reassemble HTTP requests, DNS exchanges, FTP sessions, and TLS " +
          "handshakes. Extract credentials in cleartext protocols, identify " +
          "web-shell URIs, and spot data staging and encoded payloads.",
        tools: ["wireshark", "tshark", "ngrep"],
      },
      {
        order: 4,
        title: "Detection & Hunting with Zeek/Suricata",
        body:
          "Run Zeek over the PCAP to generate structured conn, dns, http, " +
          "ssl, files, and notice logs; correlate them with Suricata alerts " +
          "for known-bad signatures. Hunt for beaconing intervals, DGA " +
          "domains, long DNS TXT answers (tunneling), and large outbound " +
          "transfers.",
        tools: ["zeek", "suricata", "tshark"],
      },
      {
        order: 5,
        title: "Extraction & Reporting",
        body:
          "Export transferred objects (Wireshark — Export Objects, or " +
          "zeek-cut + files.log), carve executables and documents, and hash " +
          "every artefact. Build the network attack timeline, map source ↔ " +
          "destination mappings to your host findings, and deliver the IOC " +
          "package for blocking and hunting.",
        tools: ["wireshark", "sha256sum", "strings"],
      },
    ],
    deliverables: [
      "Identified attacker infrastructure (C2 IPs, domains, URLs)",
      "Malicious flows and beaconing patterns with source/destination mapping",
      "Extracted files and payloads with SHA256 hashes",
      "Estimated data exfiltration volume and channels",
      "IOC package (IPs, domains, URLs, hashes) for blocking and detection",
    ],
    tools: [
      "wireshark",
      "tshark",
      "tcpdump",
      "zeek",
      "suricata",
      "capinfos",
      "sha256sum",
    ],
    icon: "Network",
  },
  {
    slug: "linux",
    title: "Forensic Investigation of a Compromised Linux Server",
    subtitle: "Persistence, Attack Vector, and Attacker Actions",
    description:
      "Trace the attack vector, persistence mechanisms, and attacker actions " +
      "on a compromised Linux server. Covers volatile collection, log " +
      "analysis, persistence hunting, SUID detection, and evidence hashing — " +
      "a complete host forensics workflow for Linux.",
    objective:
      "Analyze a compromised Linux server to identify the initial attack " +
      "vector, the persistence mechanisms planted by the attacker, and the " +
      "commands they executed.",
    context:
      "A Linux server (web or SSH-facing) shows signs of compromise: " +
      "suspicious SSH connections, modified system files, or unknown " +
      "processes. You have access to the disk — either a forensic image or " +
      "direct read-only access — and must reconstruct the intrusion without " +
      "destroying evidence.",
    steps: [
      {
        order: 1,
        title: "Volatile Data Collection",
        body:
          "Capture the live state first: running processes (ps aux), network " +
          "connections (ss -tulpn), logged-in users (w, last), loaded kernel " +
          "modules (lsmod), and open files (lsof). Volatile data disappears " +
          "on reboot — always collect it before touching the disk.",
        tools: ["ps", "ss", "w", "last", "lsmod", "lsof"],
      },
      {
        order: 2,
        title: "Log Analysis",
        body:
          "Examine /var/log/auth.log (or /var/log/secure on RHEL-family " +
          "distros) for failed and successful SSH authentication attempts. " +
          "Check /var/log/syslog for kernel errors and service crashes. Use " +
          "journalctl if systemd is present to correlate events across " +
          "services. Look for brute-force patterns and successful logins from " +
          "unusual geographies.",
        tools: ["journalctl", "grep", "awk", "lastlog"],
      },
      {
        order: 3,
        title: "Persistence Hunt",
        body:
          "Check crontabs (crontab -l, /etc/cron.*), systemd services " +
          "(systemctl list-unit-files), user shell init files (.bashrc, " +
          ".profile, .bash_profile), and SSH authorized keys " +
          "(~/.ssh/authorized_keys). Also check LD_PRELOAD in /etc/ld.so.preload " +
          "and PAM modules — favorite spots for Linux rootkit persistence.",
        tools: ["crontab", "systemctl", "find", "cat", "chkrootkit"],
      },
      {
        order: 4,
        title: "File System Analysis",
        body:
          "Find recently modified files (find / -mtime -7), suspicious SUID " +
          "binaries (find / -perm -4000 -type f), and hidden files in /tmp, " +
          "/var/tmp, and /dev/shm — common drop zones. Check for deleted-but-" +
          "open files (lsof +L1) that an attacker may still be using.",
        tools: ["find", "lsof", "stat", "file", "rkhunter"],
      },
      {
        order: 5,
        title: "Evidence Extraction & Reporting",
        body:
          "Copy suspicious files to your evidence directory, compute SHA256 " +
          "hashes for integrity, and search for strings (strings, grep). " +
          "Check for persistent outbound connections (ss -tupn) and " +
          "reverse-shell patterns. Correlate file mtimes with log entries to " +
          "build the attack timeline.",
        tools: ["sha256sum", "strings", "grep", "ss", "auditd"],
      },
    ],
    deliverables: [
      "Initial attack vector (e.g., SSH brute force, web exploitation, stolen key)",
      "Identified persistence mechanisms (cron, systemd, LD_PRELOAD, authorized_keys)",
      "Commands executed by the attacker (from history, logs, auditd)",
      "Malicious files and binaries with SHA256 hashes",
      "Remediation and hardening recommendations",
    ],
    tools: [
      "journalctl",
      "auditd",
      "chkrootkit",
      "rkhunter",
      "sha256sum",
      "strings",
      "lsof",
    ],
    icon: "Terminal",
  },
];
