#!/usr/bin/env python3
# Active Directory Attack Simulation Framework (ADASF)
# For authorized security testing only

import base64
import argparse
import json
import logging
import os
import random
import string
import sys
import tempfile
import warnings
from datetime import datetime
from getpass import getpass
from typing import Dict, List, Optional, Tuple

# Suppress deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

# Third-party imports
try:
    from impacket import version
    from impacket.dcerpc.v5 import transport, samr, lsat, lsad, wkst, srvs, scmr
    from impacket.dcerpc.v5.dtypes import NULL
    from impacket.dcerpc.v5.rpcrt import DCERPCException
    from impacket.smbconnection import SMBConnection, SessionError
    from impacket.ldap import ldap as ldap_impacket
    from impacket.krb5 import constants
    from impacket.krb5.asn1 import TGS_REP
    from impacket.krb5.kerberosv5 import getKerberosTGT, getKerberosTGS
    from impacket.krb5.types import Principal
    from impacket.spnego import SPNEGO_NegTokenInit, TypesMech
    
    import ldap3
    from ldap3.core.exceptions import LDAPException
    import dns.resolver
    import requests
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
except ImportError as e:
    print(f"Missing dependency: {e}")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('adasf.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('ADASF')

class ADSimulator:
    """Main class for Active Directory attack simulation"""
    
    def __init__(self, domain: str, username: str, password: str = None, 
                 hashes: str = None, dc_ip: str = None, 
                 safe_mode: bool = True):
        """
        Initialize the AD simulator
        
        :param domain: Target domain (e.g., corp.local)
        :param username: Username for authentication
        :param password: Password for authentication
        :param hashes: NTLM hashes (LM:NT) for pass-the-hash
        :param dc_ip: IP address of domain controller
        :param safe_mode: Enable to prevent actual exploitation
        """
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.dc_ip = dc_ip
        self.safe_mode = safe_mode
        self.ldap_conn = None
        self.smb_conn = None
        self.kerberos_tgt = None
        
        # Results storage
        self.findings = {
            'recon': [],
            'privilege_escalation': [],
            'lateral_movement': [],
            'data_exfiltration': []
        }
        
        # Initialize C2 simulation
        self.c2_key = self._generate_c2_key()
        self.c2_cipher = Fernet(self.c2_key)
        self.c2_server = "http://localhost:8080"  # Simulated C2
        
        # Connect to AD services
        self._establish_connections()

    def _generate_c2_key(self) -> bytes:
        """Generate encryption key for C2 communications"""
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return Fernet(base64.urlsafe_b64encode(kdf.derive(b'adasf-c2-key')))

    def _establish_connections(self) -> bool:
        """Establish LDAP and SMB connections"""
        return self._ldap_connect() and self._smb_connect()

    def _ldap_connect(self) -> bool:
        """Establish LDAP connection to domain controller"""
        try:
            server = ldap3.Server(
                self.dc_ip, 
                get_info=ldap3.ALL,
                use_ssl=False,
                allowed_referral_hosts=[('*', True)]
            )
            
            if self.hashes:
                lmhash, nthash = self.hashes.split(':')
                auth = ldap3.NTLM
                creds = f"{lmhash}:{nthash}"
            else:
                auth = ldap3.NTLM
                creds = self.password
                
            self.ldap_conn = ldap3.Connection(
                server,
                user=f"{self.domain}\\{self.username}",
                password=creds,
                authentication=auth,
                auto_bind=True,
                raise_exceptions=True
            )
            
            logger.info(f"LDAP connection established to {self.dc_ip}")
            return True
        except LDAPException as e:
            logger.error(f"LDAP connection failed: {e}")
            return False

    def _smb_connect(self) -> bool:
        """Establish SMB connection to domain controller"""
        try:
            self.smb_conn = SMBConnection(self.dc_ip, self.dc_ip)
            
            if self.hashes:
                lmhash, nthash = self.hashes.split(':')
                self.smb_conn.login(
                    self.username, 
                    '', 
                    self.domain, 
                    lmhash, 
                    nthash
                )
            else:
                self.smb_conn.login(
                    self.username, 
                    self.password, 
                    self.domain
                )
                
            logger.info(f"SMB connection established to {self.dc_ip}")
            return True
        except SessionError as e:
            logger.error(f"SMB connection failed: {e}")
            return False

    def run_recon_phase(self) -> Dict:
        """Execute all reconnaissance modules"""
        logger.info("Starting reconnaissance phase")
        
        results = {
            'domain_users': self.enumerate_domain_users(),
            'domain_groups': self.enumerate_domain_groups(),
            'domain_computers': self.enumerate_domain_computers(),
            'ou_structure': self.enumerate_ou_structure(),
            'gpo_info': self.enumerate_gpos(),
            'trusts': self.enumerate_domain_trusts()
        }
        
        self.findings['recon'].extend(results.values())
        return results

    def enumerate_domain_users(self) -> List[Dict]:
        """Enumerate all domain users with key attributes"""
        if not self.ldap_conn:
            return []
            
        search_filter = '(objectClass=user)'
        attributes = [
            'sAMAccountName', 'userPrincipalName', 'displayName',
            'description', 'memberOf', 'lastLogon', 'pwdLastSet',
            'userAccountControl', 'servicePrincipalName'
        ]
        
        try:
            self.ldap_conn.search(
                search_base=self._domain_dn(),
                search_filter=search_filter,
                attributes=attributes,
                size_limit=0
            )
            
            users = []
            for entry in self.ldap_conn.entries:
                user = {attr: str(getattr(entry, attr)) 
                       for attr in attributes 
                       if hasattr(entry, attr)}
                users.append(user)
                
            logger.info(f"Enumerated {len(users)} domain users")
            return users
        except LDAPException as e:
            logger.error(f"User enumeration failed: {e}")
            return []

    def enumerate_domain_groups(self) -> List[Dict]:
        """Enumerate all domain groups with members"""
        if not self.ldap_conn:
            return []
            
        search_filter = '(objectClass=group)'
        attributes = [
            'sAMAccountName', 'description', 'member',
            'managedBy', 'groupType', 'memberOf'
        ]
        
        try:
            self.ldap_conn.search(
                search_base=self._domain_dn(),
                search_filter=search_filter,
                attributes=attributes,
                size_limit=0
            )
            
            groups = []
            for entry in self.ldap_conn.entries:
                group = {
                    'name': str(entry.sAMAccountName),
                    'description': str(entry.description) if hasattr(entry, 'description') else '',
                    'members': [str(m) for m in entry.member.values] if hasattr(entry, 'member') else []
                }
                groups.append(group)
                
            logger.info(f"Enumerated {len(groups)} domain groups")
            return groups
        except LDAPException as e:
            logger.error(f"Group enumeration failed: {e}")
            return []

    def _domain_dn(self) -> str:
        """Convert domain name to DN format"""
        return f"DC={self.domain.replace('.', ',DC=')}"

    def run_privilege_escalation_checks(self) -> Dict:
        """Execute all privilege escalation checks"""
        logger.info("Starting privilege escalation checks")
        
        results = {
            'kerberoastable': self.check_kerberoastable_accounts(),
            'asreproastable': self.check_asreproastable_accounts(),
            'unconstrained_delegation': self.check_unconstrained_delegation(),
            'acl_vulnerabilities': self.check_acl_vulnerabilities(),
            'gpo_vulnerabilities': self.check_gpo_vulnerabilities()
        }
        
        self.findings['privilege_escalation'].extend(results.values())
        return results

    def check_kerberoastable_accounts(self) -> List[Dict]:
        """Identify accounts vulnerable to Kerberoasting"""
        if not self.ldap_conn:
            return []
            
        search_filter = (
            '(&(objectClass=user)(servicePrincipalName=*)'
            '(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
        )
        attributes = ['sAMAccountName', 'servicePrincipalName']
        
        try:
            self.ldap_conn.search(
                search_base=self._domain_dn(),
                search_filter=search_filter,
                attributes=attributes,
                size_limit=0
            )
            
            vulnerable = []
            for entry in self.ldap_conn.entries:
                vulnerable.append({
                    'username': str(entry.sAMAccountName),
                    'spns': [str(spn) for spn in entry.servicePrincipalName]
                })
                
            logger.info(f"Found {len(vulnerable)} kerberoastable accounts")
            return vulnerable
        except LDAPException as e:
            logger.error(f"Kerberoasting check failed: {e}")
            return []

    def simulate_kerberoasting(self, username: str) -> Optional[Dict]:
        """Simulate Kerberoasting attack (safe mode only extracts SPNs)"""
        if self.safe_mode:
            logger.info("Safe mode enabled - simulating Kerberoasting")
            return {
                'username': username,
                'status': 'simulated',
                'ticket': 'simulated_ticket_data'
            }
            
        # Actual Kerberoasting would go here in non-safe mode
        # This is for lab environments where safe_mode=False is explicitly set
        try:
            # This is a placeholder for actual Kerberoasting code
            # In a real tool, you would request TGS tickets here
            logger.warning("Actual Kerberoasting simulation would occur here")
            return None
        except Exception as e:
            logger.error(f"Kerberoasting simulation failed: {e}")
            return None

    def run_lateral_movement_simulations(self, target_host: str) -> Dict:
        """Execute lateral movement simulations"""
        logger.info(f"Starting lateral movement simulations to {target_host}")
        
        results = {
            'wmi_execution': self.simulate_wmi_execution(target_host),
            'winrm_execution': self.simulate_winrm_execution(target_host),
            'smb_execution': self.simulate_smb_execution(target_host),
            'schtasks_creation': self.simulate_schtasks_creation(target_host)
        }
        
        self.findings['lateral_movement'].extend(results.values())
        return results

    def simulate_wmi_execution(self, target: str) -> Dict:
        """Simulate WMI lateral movement"""
        if self.safe_mode:
            logger.info("Safe mode enabled - simulating WMI execution")
            return {
                'target': target,
                'technique': 'WMI',
                'status': 'simulated',
                'command': 'whoami',
                'output': f'{self.domain}\\{self.username}'
            }
            
        # Actual WMI execution would go here in non-safe mode
        return {'status': 'not_attempted'}

    def run_data_exfiltration_simulations(self) -> Dict:
        """Execute data exfiltration simulations"""
        logger.info("Starting data exfiltration simulations")
        
        results = {
            'sensitive_files': self.find_sensitive_files(),
            'credential_search': self.search_for_credentials(),
            'registry_extraction': self.extract_registry_secrets()
        }
        
        self.findings['data_exfiltration'].extend(results.values())
        return results

    def generate_report(self, format: str = 'json') -> bool:
        """Generate assessment report in specified format"""
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"adasf_report_{timestamp}.{format}"
            
            with open(filename, 'w') as f:
                if format == 'json':
                    json.dump(self.findings, f, indent=4)
                elif format == 'html':
                    # HTML report generation would go here
                    f.write(self._generate_html_report())
                else:
                    raise ValueError(f"Unsupported report format: {format}")
                    
            logger.info(f"Report generated: {filename}")
            return True
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return False

    def _generate_html_report(self) -> str:
        """Generate HTML formatted report"""
        # This would be a more sophisticated HTML generator in a real tool
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

def main():
    parser = argparse.ArgumentParser(
        description="Active Directory Attack Simulation Framework",
        epilog="Use only in authorized testing environments"
    )
    
    # Authentication options
    auth_group = parser.add_argument_group('Authentication')
    auth_group.add_argument('-d', '--domain', required=True, help="Target domain")
    auth_group.add_argument('-u', '--username', required=True, help="Auth username")
    auth_group.add_argument('-p', '--password', help="Auth password")
    auth_group.add_argument('-H', '--hashes', help="NTLM hashes (LM:NT)")
    auth_group.add_argument('--dc-ip', required=True, help="Domain controller IP")
    
    # Operation modes
    mode_group = parser.add_argument_group('Operation Modes')
    mode_group.add_argument('--recon', action='store_true', help="Run reconnaissance only")
    mode_group.add_argument('--privesc', action='store_true', help="Run privilege escalation checks")
    mode_group.add_argument('--lateral', metavar='TARGET', help="Simulate lateral movement to target")
    mode_group.add_argument('--exfil', action='store_true', help="Simulate data exfiltration")
    mode_group.add_argument('--full', action='store_true', help="Run all phases")
    
    # Additional options
    parser.add_argument('--safe-mode', action='store_true', default=True,
                      help="Enable safe simulation mode (default)")
    parser.add_argument('--no-safe-mode', action='store_false', dest='safe_mode',
                      help="Disable safe simulation mode (caution)")
    parser.add_argument('--report-format', choices=['json', 'html'], default='json',
                      help="Report output format")
    
    args = parser.parse_args()
    
    # Validate authentication
    if not args.password and not args.hashes:
        args.password = getpass("Password: ")
    
    # Initialize simulator
    simulator = ADSimulator(
        domain=args.domain,
        username=args.username,
        password=args.password,
        hashes=args.hashes,
        dc_ip=args.dc_ip,
        safe_mode=args.safe_mode
    )
    
    # Execute requested phases
    if args.recon or args.full:
        simulator.run_recon_phase()
    
    if args.privesc or args.full:
        simulator.run_privilege_escalation_checks()
    
    if args.lateral or args.full:
        target = args.lateral if args.lateral else 'WIN-EXAMPLE'
        simulator.run_lateral_movement_simulations(target)
    
    if args.exfil or args.full:
        simulator.run_data_exfiltration_simulations()
    
    # Generate report
    simulator.generate_report(args.report_format)

if __name__ == '__main__':
    main()
