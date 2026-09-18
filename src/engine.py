# pathasm/src/engine.py
import networkx as nx
import logging
from typing import Dict, List, Any

logger = logging.getLogger("PathAsm.Engine")
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("[PathAsm-Engine] %(asctime)s - %(levelname)s - %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.INFO)

class PathAsmCoreEngine:
    def __init__(self, infrastructure_data: Dict[str, Any]):
        if not isinstance(infrastructure_data, dict):
            raise TypeError("Infrastructure input payload must be a valid dictionary.")
        
        # Keep track of SID-to-Name mappings for universal lookup cross-compatibility
        self.sid_to_name: Dict[str, str] = {}
        self.name_to_sid: Dict[str, str] = {}
        
        if "data" in infrastructure_data and isinstance(infrastructure_data["data"], list):
            logger.info("[*] SharpHound signature verified. Normalizing dataset schema...")
            self.data = self._translate_sharphound_format(infrastructure_data)
        else:
            logger.info("[*] Native PathAsm graph schema signature verified.")
            self.data = infrastructure_data
            
        self.graph = nx.DiGraph()
        self._build_graph()

    def _translate_sharphound_format(self, bh_data: Dict[str, Any]) -> Dict[str, Any]:
        normalized = {"subnets": [], "firewall_rules": []}
        records = bh_data.get("data", [])
        
        # Pass 1: Build identity lookup tables
        for entry in records:
            sid = entry.get("ObjectIdentifier", "").lower().strip()
            props = entry.get("Properties", {})
            name = props.get("name", sid).lower().strip()
            if sid and name:
                self.sid_to_name[sid] = name
                self.name_to_sid[name] = sid
                
        # Pass 2: Process nodes and relationships using standardized strings
        for entry in records:
            sid = entry.get("ObjectIdentifier", "").lower().strip()
            if not sid:
                continue
                
            props = entry.get("Properties", {})
            name = props.get("name", sid).lower().strip()
            os_name = str(props.get("operatingSystem", "")).lower()
            base_risk = 3.5 if ("2012" in os_name or "2008" in os_name) else 1.5
            is_dc = "dc" in name or props.get("highvalue", False) is True
            
            normalized["subnets"].append({
                "id": name,  # Standardize on human-readable names for frontend visualization sync
                "name": f"Live Principal: {name.upper()}",
                "base_attack_vector_risk": base_risk,
                "edr_monitoring_multiplier": 6.0 if is_dc else 1.2
            })
            
            # Translate SIDs inside relations back to target names cleanly
            for ace in entry.get("Aces", []):
                if isinstance(ace, dict):
                    src_sid = ace.get("PrincipalId", "").lower().strip()
                    src_name = self.sid_to_name.get(src_sid, src_sid)
                    right_name = ace.get("RightName", "").upper().strip()
                    if src_name and name:
                        normalized["firewall_rules"].append({
                            "source": src_name,
                            "destination": name,
                            "rule_id": f"AD_ACE_{right_name}"
                        })
                    
            for member in entry.get("Members", []):
                m_sid = member.lower().strip() if isinstance(member, str) else member.get("ObjectIdentifier", "").lower().strip()
                m_name = self.sid_to_name.get(m_sid, m_sid)
                if m_name and name:
                    normalized["firewall_rules"].append({
                        "source": m_name,
                        "destination": name,
                        "rule_id": "AD_MEMBEROF"
                    })
                    
            for session in entry.get("Sessions", []):
                if isinstance(session, dict):
                    comp_sid = session.get("ComputerSID", "").lower().strip()
                    user_sid = session.get("UserId", "").lower().strip()
                    comp_name = self.sid_to_name.get(comp_sid, comp_sid)
                    user_name = self.sid_to_name.get(user_sid, user_sid)
                    if comp_name and user_name:
                        normalized["firewall_rules"].append({
                            "source": user_name,
                            "destination": comp_name,
                            "rule_id": "INTERM_LAN_SESSION"
                        })

            for delegation in entry.get("AllowedToDelegate", []):
                if isinstance(delegation, dict):
                    dest_sid = delegation.get("ObjectIdentifier", "").lower().strip()
                    dest_name = self.sid_to_name.get(dest_sid, dest_sid)
                    reason = delegation.get("Reason", "GENERIC_ALLOW")
                    if dest_name:
                        normalized["firewall_rules"].append({
                            "source": name,
                            "destination": dest_name,
                            "rule_id": reason
                        })
                    
        return normalized
    def _build_graph(self) -> None:
        subnets = self.data.get("subnets", [])
        firewall_rules = self.data.get("firewall_rules", [])

        for subnet in subnets:
            subnet_id = subnet.get("id")
            if not subnet_id:
                continue
            self.graph.add_node(
                subnet_id,
                name=subnet.get("name", subnet_id),
                base_risk=float(subnet.get("base_attack_vector_risk", 1.5)),
                edr_multiplier=float(subnet.get("edr_monitoring_multiplier", 1.0))
            )

        for rule in firewall_rules:
            source = rule.get("source")
            destination = rule.get("destination")
            rule_id = rule.get("rule_id", "GENERIC_ALLOW")

            if not source or not destination:
                continue

            # Universal Auto-Registration for un-declared elements
            if not self.graph.has_node(source):
                self.graph.add_node(source, name=f"Live Principal: {source.upper()}", base_risk=1.5, edr_multiplier=1.0)
            if not self.graph.has_node(destination):
                self.graph.add_node(destination, name=f"Live Principal: {destination.upper()}", base_risk=1.5, edr_multiplier=1.0)

            dest_node = self.graph.nodes[destination]
            base_risk = dest_node.get("base_risk", 1.5)
            edr_mult = dest_node.get("edr_multiplier", 1.0)

            vector_exposure_weight = {
                "AD_MEMBEROF": 0.5,
                "AD_ACE_GENERICALL": 12.0,
                "AD_ACE_WRITEDACL": 15.0,
                "INTERM_LAN_SESSION": 95.0,  # High risk rating to force routing divergence
                "AD_CONSTRAINED_DELEGATION": 5.0
            }.get(rule_id.upper(), 40.0)

            telemetry_weight = (base_risk * edr_mult) + vector_exposure_weight

            self.graph.add_edge(
                source, destination,
                shortest_hop_cost=1.0,
                stealth_cost=telemetry_weight,
                rule_id=rule_id
            )

def calculate_adversarial_routes(self, source: str, target: str) -> Dict[str, Any]:
        # 1. Clean, strip, and normalize inbound lookup variables safely
        source = source.lower().strip()
        target = target.lower().strip()
        
        # 2. SEAMLESS FALLBACK RESOLUTION: Cross-reference alternate strings if direct matching fails
        if not self.graph.has_node(source):
            # Check if an alternate case-insensitive variant exists anywhere inside the active graph
            graph_nodes_lower = [str(n).lower() for n in self.graph.nodes]
            if source in graph_nodes_lower:z
                # Dynamic mapping alignment catch: match the exact syntax variant present in the database
            source = list(self.graph.nodes)[graph_nodes_lower.index(source)]
        else:
                logger.warning(f"Origin search variable missing from layout matrix: {source}")
                return {"error": f"The entry vector principal '{source}' could not be located inside the topological infrastructure matrix."}
                
        if not self.graph.has_node(target):
            graph_nodes_lower = [str(n).lower() for n in self.graph.nodes]
            if target in graph_nodes_lower:
                target = list(self.graph.nodes)[graph_nodes_lower.index(target)]
            else:
                logger.warning(f"Destination search variable missing from layout matrix: {target}")
                return {"error": f"The destination objective principal '{target}' could not be located inside the topological infrastructure matrix."}

        results: Dict[str, Any] = {}
        fallback_graph = self.graph.to_undirected()

        # 3. Universal Path Calculation Engine Modules
        try:
            shortest_path = nx.shortest_path(self.graph, source=source, target=target, weight="shortest_hop_cost")
        except (nx.NetworkXNoPath, nx.NetworkXError, KeyError):
            try:
                shortest_path = nx.shortest_path(fallback_graph, source=source, target=target, weight="shortest_hop_cost")
            except (nx.NetworkXNoPath, nx.NetworkXError, KeyError):
                shortest_path = None

        if shortest_path:
            shortest_penalty = 0.0
            for u, v in zip(shortest_path[:-1], shortest_path[1:]):
                if self.graph.has_edge(u, v):
                    shortest_penalty += self.graph[u][v].get("stealth_cost", 1.0)
                elif fallback_graph.has_edge(u, v):
                    shortest_penalty += fallback_graph[u][v].get("stealth_cost", 1.0)
            
            results["shortest_path"] = {
                "route": shortest_path,
                "total_hops": len(shortest_path) - 1,
                "accumulated_telemetry_penalty": round(shortest_penalty, 2)
            }
        else:
            results["shortest_path"] = {"error": "Unreachable"}

        try:
            stealthy_path = nx.shortest_path(self.graph, source=source, target=target, weight="stealth_cost")
        except (nx.NetworkXNoPath, nx.NetworkXError, KeyError):
            try:
                stealthy_path = nx.shortest_path(fallback_graph, source=source, target=target, weight="stealth_cost")
            except (nx.NetworkXNoPath, nx.NetworkXError, KeyError):
                stealthy_path = None

        if stealthy_path:
            stealthy_penalty = 0.0
            for u, v in zip(stealthy_path[:-1], stealthy_path[1:]):
                if self.graph.has_edge(u, v):
                    stealthy_penalty += self.graph[u][v].get("stealth_cost", 1.0)
                elif fallback_graph.has_edge(u, v):
                    stealthy_penalty += fallback_graph[u][v].get("stealth_cost", 1.0)
                    
            results["stealthiest_path"] = {
                "route": stealthy_path,
                "total_hops": len(stealthy_path) - 1,
                "accumulated_telemetry_penalty": round(stealthy_penalty, 2)
            }
        else:
            results["stealthiest_path"] = {"error": "Unreachable"}

        return results
