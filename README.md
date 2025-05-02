# Active Directory Attack Simulation Framework (ADASF)

A Python-based framework for simulating Active Directory attack techniques in authorized security testing environments.

## Features

- **Comprehensive Reconnaissance**:
  - Domain user/group/computer enumeration
  - OU structure mapping
  - GPO and trust relationship discovery

- **Privilege Escalation Checks**:
  - Kerberoasting detection
  - AS-REP roasting detection
  - Unconstrained delegation identification
  - ACL vulnerability assessment

- **Lateral Movement Simulations**:
  - WMI execution
  - WinRM execution
  - SMB file operations
  - Scheduled task creation

- **Safe Testing Environment**:
  - Non-destructive safe mode (default)
  - Simulated attack patterns
  - Comprehensive logging

## Installation

### Prerequisites
- Python 3.8+
- Active Directory test environment
- Domain credentials (for authentication)

### Setup
bash - 
git clone https://github.com/yourusername/ADASF.git
cd ADASF
pip install -r requirements.txt
