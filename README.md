# ADASF — Active Directory Attack Simulation Framework

**ADASF** is a Python-based framework that *safely simulates* Active Directory attack techniques for authorized security testing, red-team training, and blue-team detection validation. It focuses on realistic, non-destructive simulations and rich logging so teams can test detection and response without performing harmful actions by default.

---

## Key features
- **Comprehensive reconnaissance (implemented / simulated)**
  - Domain user & group enumeration — *implemented*  
  - Domain computer / OU / GPO / trust enumeration — *safe stubs (planned)*
- **Privilege escalation checks**
  - Kerberoastable detection — *implemented (SPN enumeration; simulation only)*  
  - AS-REP roast detection, unconstrained delegation, ACL/GPO checks — *safe stubs*
- **Lateral movement (simulated only)**
  - WMI, WinRM, SMB file operations, scheduled tasks — *safe simulation*
- **Safe testing environment**
  - Default **safe mode = ON** (non-destructive)  
  - `--no-safe-mode` exists but non-safe actions must be implemented in lab only
- **Logging & Reporting**
  - Logs to `adasf.log` + console  
  - Generates timestamped JSON (default) or HTML reports

---

## Safety & Ethics
- **Run only on lab/test environments with explicit authorization.**  
- Default `safe_mode=True` ensures non-destructive actions.  
- Pass-the-hash (NTLM) behavior differs between SMB and LDAP; LDAP with hashes is skipped.  
- Report files: `adasf_report_YYYYMMDD_HHMMSS.json` / `.html`.

---

## Installation
```bash
git clone https://github.com/yourorg/ADASF.git
cd ADASF
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
