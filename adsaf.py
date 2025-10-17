#!/usr/bin/env python3
# Active Directory Attack Simulation Framework (ADASF)
# For authorized security testing only

import base64
import argparse
import json
import logging
import os
import sys
import warnings
from datetime import datetime
from getpass import getpass
from typing import Dict, List, Optional

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Third-party imports
try:
    from impacket.smbconnection import SMBConnection, SessionError
    import ldap3
    from ldap3.core.exceptions import LDAPException
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print(f"Missing dependency: {e}. Please install required packages (impacket, ldap3, cryptography).")
    sys.exit(1)

# Configure logging (file + console). Restrict file permissions on POSIX.
LOG_FILE = 'adasf.log'
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
# Attempt to restrict log file permissions to owner only (POSIX)
try:
    os.chmod(LOG_FILE, 0o600)
except Exception:
    pass

logger = logging.getLogger('ADASF')


class ADSimulator:
    """Main class for Active Directory attack simulation"""

    def __init__(self, domain: str, username: str, password: str = None,
                 hashes: str = None, dc_ip: str = None,
                 safe_mode: bool = True):
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.dc_ip = dc_ip
        self.safe_mode = safe_mode
        self.ldap_conn: Optional[ldap3.Connection] = None
        self.smb_conn: Optional[SMBConnection] = None

        # Findings
        self.findings = {
            'recon': [],
            'privilege_escalation': [],
            'lateral_movement': [],
            'data_exfiltration': []
        }

        # C2 simulation: derive a stable key and store salt so we can reproduce if needed
        self._c2_salt = os.urandom(16)
        self.c2_key = self._derive_c2_key(self._c2_salt)
        self.c2_cipher = Fernet(self.c2_key)
        self.c2_server = "http://localhost:8080"  # Simulated C2

        # Try to connect to services (will log failures but not raise)
        self._establish_connections()

    def _derive_c2_key(self, salt: bytes) -> bytes:
        """Derive a 32-byte key and return base64-urlsafe-encoded key for Fernet"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        raw = kdf.derive(b'adasf-c2-key')
        return base64.urlsafe_b64encode(raw)

    def _establish_connections(self) -> bool:
        success = True
        ok_ldap = self._ldap_connect()
        ok_smb = self._smb_connect()
        success = ok_ldap or ok_smb
        return success

    def _ldap_connect(self) -> bool:
        """Establish LDAP connection to domain controller"""
        if not self.dc_ip:
            logger.warning("No DC IP provided; skipping LDAP connect.")
            return False
        try:
            server = ldap3.Server(self.dc_ip, get_info=ldap3.ALL)
            # ldap3 expects username/password; NTLM hash 'pass-the-hash' isn't directly supported here.
            if self.hashes:
                logger.warning("Hashes provided. ldap3 does not support pass-the-hash directly; skipping LDAP bind.")
                return False
            else:
                user = f"{self.domain}\\{self.username}"
                self.ldap_conn = ldap3.Connection(server, user=user, password=self.password,
                                                  authentication=ldap3.NTLM, auto_bind=True, raise_exceptions=False)
                if not self.ldap_conn.bound:
                    logger.error("LDAP bind failed (invalid credentials or configuration).")
                    self.ldap_conn = None
                    return False
            logger.info(f"LDAP connection established to {self.dc_ip}")
            return True
        except LDAPException as e:
            logger.error(f"LDAP connection failed: {e}")
            self.ldap_conn = None
            return False
        except Exception as e:
            logger.error(f"Unexpected LDAP error: {e}")
            self.ldap_conn = None
            return False

    def _smb_connect(self) -> bool:
        """Establish SMB connection to domain controller"""
        if not self.dc_ip:
            logger.warning("No DC IP provided; skipping SMB connect.")
            return False
        try:
            self.smb_conn = SMBConnection(self.dc_ip, self.dc_ip)
            # SMBConnection.login signature: login(self, user, password, domain='', lmhash='', nthash='')
            if self.hashes:
                try:
                    lmhash, nthash = self.hashes.split(':')
                except ValueError:
                    lmhash = ''
                    nthash = ''
                self.smb_conn.login(self.username, '', self.domain, lmhash, nthash)
            else:
                self.smb_conn.login(self.username, self.password or '', self.domain)
            logger.info(f"SMB connection established to {self.dc_ip}")
            return True
        except SessionError as e:
            logger.error(f"SMB connection failed: {e}")
            self.smb_conn = None
            return False
        except Exception as e:
            logger.error(f"Unexpected SMB error: {e}")
            self.smb_conn = None
            return False

    def _domain_dn(self) -> str:
        """Convert domain name to DN format (example: corp.local -> DC=corp,DC=local)"""
        parts = self.domain.split('.')
        return ','.join(f"DC={p}" for p in parts)

    # -------------------------
    # Reconnaissance
    # -------------------------
    def run_recon_phase(self) -> Dict:
        logger.info("Starting reconnaissance phase")
        results = {
            'domain_users': self.enumerate_domain_users(),
            'domain_groups': self.enumerate_domain_groups(),
            'domain_computers': self.enumerate_domain_computers(),
            'ou_structure': self.enumerate_ou_structure(),
            'gpo_info': self.enumerate_gpos(),
            'trusts': self.enumerate_domain_trusts()
        }
        self.findings['recon'].append(results)
        return results

    def enumerate_domain_users(self) -> List[Dict]:
        if not self.ldap_conn:
            logger.warning("LDAP connection not available; skipping user enumeration.")
            return []
        search_filter = '(objectClass=user)'
        attributes = [
            'sAMAccountName', 'userPrincipalName', 'displayName',
            'description', 'memberOf', 'lastLogon', 'pwdLastSet',
            'userAccountControl', 'servicePrincipalName'
        ]
        try:
            self.ldap_conn.search(search_base=self._domain_dn(), search_filter=search_filter,
                                  attributes=attributes, size_limit=0)
            users = []
            for entry in self.ldap_conn.entries:
                ad = entry.entry_attributes_as_dict
                user = {k: ad.get(k) for k in attributes if k in ad}
                users.append(user)
            logger.info(f"Enumerated {len(users)} domain users")
            return users
        except LDAPException as e:
            logger.error(f"User enumeration failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during user enumeration: {e}")
            return []

    def enumerate_domain_groups(self) -> List[Dict]:
        if not self.ldap_conn:
            logger.warning("LDAP connection not available; skipping group enumeration.")
            return []
        search_filter = '(objectClass=group)'
        attributes = ['sAMAccountName', 'description', 'member', 'managedBy', 'groupType', 'memberOf']
        try:
            self.ldap_conn.search(search_base=self._domain_dn(), search_filter=search_filter,
                                  attributes=attributes, size_limit=0)
            groups = []
            for entry in self.ldap_conn.entries:
                ad = entry.entry_attributes_as_dict
                groups.append({
                    'name': ad.get('sAMAccountName'),
                    'description': ad.get('description', ''),
                    'members': ad.get('member', [])
                })
            logger.info(f"Enumerated {len(groups)} domain groups")
            return groups
        except LDAPException as e:
            logger.error(f"Group enumeration failed: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error during group enumeration: {e}")
            return []

    # -------------------------
    # Priv Esc checks (stubs)
    # -------------------------
    def run_privilege_escalation_checks(self) -> Dict:
        logger.info("Starting privilege escalation checks")
        results = {
            'kerberoastable': self.check_kerberoastable_accounts(),
            'asreproastable': self.check_asreproastable_accounts(),
            'unconstrained_delegation': self.check_unconstrained_delegation(),
            'acl_vulnerabilities': self.check_acl_vulnerabilities(),
            'gpo_vulnerabilities': self.check_gpo_vulnerabilities()
        }
        self.findings['privilege_escalation'].append(results)
        return results

    def check_kerberoastable_accounts(self) -> List[Dict]:
        if not self.ldap_conn:
            logger.warning("LDAP not available; skipping Kerberoast checks.")
            return []
        search_filter = (
            '(&(objectClass=user)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        )
        attributes = ['sAMAccountName', 'servicePrincipalName']
        try:
            self.ldap_conn.search(search_base=self._domain_dn(), search_filter=search_filter,
                                  attributes=attributes, size_limit=0)
            vulnerable = []
            for entry in self.ldap_conn.entries:
                ad = entry.entry_attributes_as_dict
                vulnerable.append({
                    'username': ad.get('sAMAccountName'),
                    'spns': ad.get('servicePrincipalName', [])
                })
            logger.info(f"Found {len(vulnerable)} kerberoastable accounts")
            return vulnerable
        except Exception as e:
            logger.error(f"Kerberoasting check failed: {e}")
            return []

    # The following are safe stubs: implement lab-safe logic as needed
    def check_asreproastable_accounts(self) -> List[Dict]:
        logger.warning("AS-REP roast check not implemented — returning empty list (safe stub).")
        return []

    def check_unconstrained_delegation(self) -> List[Dict]:
        logger.warning("Unconstrained delegation check not implemented — returning empty list (safe stub).")
        return []

    def check_acl_vulnerabilities(self) -> List[Dict]:
        logger.warning("ACL vulnerability check not implemented — returning empty list (safe stub).")
        return []

    def check_gpo_vulnerabilities(self) -> List[Dict]:
        logger.warning("GPO vulnerability check not implemented — returning empty list (safe stub).")
        return []

    # -------------------------
    # Lateral movement simulation
    # -------------------------
    def run_lateral_movement_simulations(self, target_host: str) -> Dict:
        logger.info(f"Starting lateral movement simulations to {target_host}")
        results = {
            'wmi_execution': self.simulate_wmi_execution(target_host),
            'winrm_execution': self.simulate_winrm_execution(target_host),
            'smb_execution': self.simulate_smb_execution(target_host),
            'schtasks_creation': self.simulate_schtasks_creation(target_host)
        }
        self.findings['lateral_movement'].append(results)
        return results

    def simulate_wmi_execution(self, target: str) -> Dict:
        if self.safe_mode:
            logger.info("Safe mode: simulated WMI execution")
            return {'target': target, 'technique': 'WMI', 'status': 'simulated', 'command': 'whoami',
                    'output': f'{self.domain}\\{self.username}'}
        logger.warning("WMI execution in non-safe mode not implemented in this stub.")
        return {'status': 'not_attempted'}

    def simulate_winrm_execution(self, target: str) -> Dict:
        if self.safe_mode:
            logger.info("Safe mode: simulated WinRM execution")
            return {'target': target, 'technique': 'WinRM', 'status': 'simulated', 'command': 'whoami',
                    'output': f'{self.domain}\\{self.username}'}
        logger.warning("WinRM execution in non-safe mode not implemented in this stub.")
        return {'status': 'not_attempted'}

    def simulate_smb_execution(self, target: str) -> Dict:
        if self.safe_mode:
            logger.info("Safe mode: simulated SMB file operation")
            return {'target': target, 'technique': 'SMB', 'status': 'simulated', 'action': 'read', 'file': '\\\\target\\share\\demo.txt'}
        logger.warning("SMB execution in non-safe mode not implemented in this stub.")
        return {'status': 'not_attempted'}

    def simulate_schtasks_creation(self, target: str) -> Dict:
        if self.safe_mode:
            logger.info("Safe mode: simulated scheduled task creation")
            return {'target': target, 'technique': 'Schtasks', 'status': 'simulated', 'taskname': 'ADASF_demo'}
        logger.warning("schtasks creation in non-safe mode not implemented in this stub.")
        return {'status': 'not_attempted'}

    # -------------------------
    # Data exfiltration simulation (stubs)
    # -------------------------
    def run_data_exfiltration_simulations(self) -> Dict:
        logger.info("Starting data exfiltration simulations")
        results = {
            'sensitive_files': self.find_sensitive_files(),
            'credential_search': self.search_for_credentials(),
            'registry_extraction': self.extract_registry_secrets()
        }
        self.findings['data_exfiltration'].append(results)
        return results

    def find_sensitive_files(self) -> List[str]:
        logger.warning("Sensitive file search not implemented — returning empty list (safe stub).")
        return []

    def search_for_credentials(self) -> List[Dict]:
        logger.warning("Credential search not implemented — returning empty list (safe stub).")
        return []

    def extract_registry_secrets(self) -> List[Dict]:
        logger.warning("Registry extraction not implemented — returning empty list (safe stub).")
        return []

    # -------------------------
    # Utility: report
    # -------------------------
    def generate_report(self, format: str = 'json') -> bool:
        try:
            ts = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"adasf_report_{ts}.{format}"
            with open(filename, 'w', encoding='utf-8') as f:
                if format == 'json':
                    json.dump(self.findings, f, indent=4, ensure_ascii=False)
                else:
                    f.write(self._generate_html_report())
            logger.info(f"Report generated: {filename}")
            return True
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return False

    def _generate_html_report(self) -> str:
        return f"""
        <html>
        <head><title>ADASF Report - {datetime.now()}</title></head>
        <body>
        <h1>Active Directory Attack Simulation Report</h1>
        <p>Domain: {self.domain}</p>
        <p>Generated at: {datetime.now()}</p>
        <pre>{json.dumps(self.findings, indent=4)}</pre>
        </body>
        </html>
        """

    # Safe helper stubs for recon items not implemented above
    def enumerate_domain_computers(self) -> List[Dict]:
        logger.warning("Computer enumeration not implemented — returning empty list (safe stub).")
        return []

    def enumerate_ou_structure(self) -> List[Dict]:
        logger.warning("OU enumeration not implemented — returning empty list (safe stub).")
        return []

    def enumerate_gpos(self) -> List[Dict]:
        logger.warning("GPO enumeration not implemented — returning empty list (safe stub).")
        return []

    def enumerate_domain_trusts(self) -> List[Dict]:
        logger.warning("Domain trust enumeration not implemented — returning empty list (safe stub).")
        return []


def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Attack Simulation Framework",
        epilog="Use only in authorized testing environments"
    )

    # Authentication
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-d', '--domain', required=True, help="Target domain (e.g., corp.local)")
    auth_group.add_argument('-u', '--username', required=True, help="Auth username")
    auth_group.add_argument('-p', '--password', help="Auth password")
    auth_group.add_argument('-H', '--hashes', help="NTLM hashes (LM:NT)")
    auth_group.add_argument('--dc-ip', required=True, help="Domain controller IP")

    # Modes
    mode_group = parser.add_argument_group('Operation Modes')
    mode_group.add_argument('--recon', action='store_true', help="Run reconnaissance only")
    mode_group.add_argument('--privesc', action='store_true', help="Run privilege escalation checks")
    mode_group.add_argument('--lateral', metavar='TARGET', help="Simulate lateral movement to target")
    mode_group.add_argument('--exfil', action='store_true', help="Simulate data exfiltration")
    mode_group.add_argument('--full', action='store_true', help="Run all phases")

    parser.add_argument('--safe-mode', action='store_true', default=True, help="Enable safe simulation mode (default)")
    parser.add_argument('--no-safe-mode', action='store_false', dest='safe_mode', help="Disable safe simulation mode (caution)")
    parser.add_argument('--report-format', choices=['json', 'html'], default='json', help="Report output format")

    args = parser.parse_args()

    if not args.password and not args.hashes:
        args.password = getpass("Password: ")

    simulator = ADSimulator(
        domain=args.domain,
        username=args.username,
        password=args.password,
        hashes=args.hashes,
        dc_ip=args.dc_ip,
        safe_mode=args.safe_mode
    )

    if args.recon or args.full:
        simulator.run_recon_phase()

    if args.privesc or args.full:
        simulator.run_privilege_escalation_checks()

    if args.lateral or args.full:
        target = args.lateral if args.lateral else 'WIN-EXAMPLE'
        simulator.run_lateral_movement_simulations(target)

    if args.exfil or args.full:
        simulator.run_data_exfiltration_simulations()

    simulator.generate_report(args.report_format)


if __name__ == '__main__':
    main()
