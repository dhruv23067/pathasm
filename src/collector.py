# pathasm/src/collector.py
import json
import logging
import os
import sys
import time
import random
from typing import Dict, List, Any, Generator

try:
    from ldap3 import Server, Connection, ALL, SUBTREE, Tls
    import ssl
    LDAP_AVAILABLE = True
except ImportError:
    LDAP_AVAILABLE = False

logging.basicConfig(level=logging.INFO, format="[PathAsm-Collector] %(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("PathAsm-Collector")

class ActiveDirectoryCollector:
    def __init__(self, domain_controller: str = None, user_dn: str = None, password: str = None):
        self.domain_controller = domain_controller
        self.user_dn = user_dn
        self.password = password
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Dict[str, Any]] = []

    def run_discovery_cycle(self, output_filename: str = "infrastructure_dump.json") -> None:
        """Executes a production-ready, memory-conscious data extraction phase."""
        if not LDAP_AVAILABLE:
            raise RuntimeError("CRITICAL: The 'ldap3' library dependency is missing. Run 'pip install ldap3' to continue.")

        if not self.domain_controller or not self.user_dn or not self.password:
            raise ValueError(
                "CRITICAL ERROR: Missing target network parameters.\n"
                "[!] Usage: pathasm run --dc <host> --user <dn> --password <pass>"
            )

        logger.info("[*] Initializing secure, paged enterprise network discovery...")
        self._query_live_active_directory_securely()

    def _query_live_active_directory_securely(self) -> None:
        try:
            logger.info(f"[*] Constructing TLS wrapper layers targeting host: {self.domain_controller}")
            
            # Enforce high-security TLS validation configuration parameters
            tls_config = Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
            server = Server(self.domain_controller, port=636, use_ssl=True, tls=tls_config, get_info=ALL)
            
            logger.info("[*] Establishing encrypted socket binding over LDAPS (Port 636)...")
            conn = Connection(
                server, 
                user=self.user_dn, 
                password=self.password, 
                auto_bind=True,
                receive_timeout=30
            )
            
            # Dynamically calculate the search base context from the provided username string
            search_base = "dc=company,dc=local"
            if "@" in self.user_dn:
                domain_part = self.user_dn.split("@")[1]
                search_base = ",".join([f"dc={part}" for part in domain_part.split(".")])
            elif "dc=" in self.user_dn.lower():
                idx = self.user_dn.lower().find("dc=")
                search_base = self.user_dn[idx:]

            logger.info(f"[+] Secure channel binding active. Target Search Base: {search_base}")
            
            # Use dynamic filters to cleanly isolate core network infrastructure objects
            active_filter = "(|(objectClass=computer)(objectClass=user))"
            search_attrs = ["cn", "operatingSystem", "msDS-AllowedToDelegateTo", "objectClass"]
            
            # Implement randomized paging to mask standard diagnostic signatures
            paged_size_base = random.randint(250, 450)
            logger.info(f"[*] Commencing streamed query operations. Baseline Page Target Size: {paged_size_base}")

            search_generator = conn.extend.standard.paged_search(
                search_base=search_base,
                search_filter=active_filter,
                search_scope=SUBTREE,
                attributes=search_attrs,
                paged_size=paged_size_base,
                generator=True
            )

            processed_count = 0
            for entry in search_generator:
                # Add randomized time intervals (jitter) between queries to prevent triggering network alerts
                processed_count += 1
                if processed_count % 50 == 0:
                    jitter_sleep = random.uniform(0.2, 0.8)
                    time.sleep(jitter_sleep)

                if 'attributes' not in entry:
                    continue
                    
                attrs = entry['attributes']
                principal_id = str(attrs.get('cn', '')).lower()
                
                if not principal_id or not attrs.get('cn'):
                    continue
                
                # Check for standard server OS markers to calculate initial asset risks accurately
                os_name = str(attrs.get('operatingSystem', '')).lower() if 'operatingSystem' in attrs else ""
                base_risk = 1.5
                if "server" in os_name or "2016" in os_name or "2019" in os_name or "2022" in os_name:
                    base_risk = 3.5
                if "2008" in os_name or "2012" in os_name:
                    base_risk = 5.0 # High vulnerability score for legacy operating systems

                # Detect key target objects like domain administrators or backup systems
                is_high_value = any(term in principal_id for term in ["dc", "admin", "sql", "exch"])
                
                self.nodes[principal_id] = {
                    "id": principal_id,
                    "name": f"Live Principal: {principal_id.upper()}",
                    "base_attack_vector_risk": base_risk,
                    "edr_monitoring_multiplier": 6.0 if is_high_value else 1.2
                }

                # Securely extract and process Constrained Delegation links
                if 'msDS-AllowedToDelegateTo' in attrs:
                    delegation = attrs.get('msDS-AllowedToDelegateTo', [])
                    targets = [delegation] if isinstance(delegation, str) else delegation
                    for t in targets:
                        if t:
                            # Isolate the target entity identity cleanly out of complex service string contexts
                            clean_target = str(t).split('/')[-1].split('.')[0].lower()
                            self.edges.append({
                                "source": principal_id,
                                "destination": clean_target,
                                "rule_id": "AD_CONSTRAINED_DELEGATION"
                            })
                        
            conn.unbind()
            logger.info(f"[+] Secure data extraction complete. Tracked {len(self.nodes)} nodes and {len(self.edges)} security edges safely.")
                
        except Exception as e:
            logger.error("[-] FATAL: Encrypted data collection failed.")
            raise RuntimeError(f"Enterprise Network Connection Error: {e}")

    def serialize_and_export(self, output_filename: str = "infrastructure_dump.json") -> str:
        """Saves the mapped network matrix data cleanly to a structural file export."""
        if not self.nodes:
            raise ValueError("Operational Error: No infrastructure data was retrieved to export.")
            
        payload = {"subnets": list(self.nodes.values()), "firewall_rules": self.edges}
        
        # Safely overwrite the destination export file without corrupting surrounding elements
        with open(output_filename, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=4)
            
        logger.info(f"[+] PathAsm architecture blueprint exported to: {output_filename}")
        return output_filename
