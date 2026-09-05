import os
import sys
import logging
import networkx as nx

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ingestor import PathAsmTopologyIngestor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class PathAsmContextEngine:
    """Advanced routing engine enforcing network constraints and token requirements."""
    def __init__(self, base_graph: nx.DiGraph):
        self.master_graph = base_graph

    def compute_constrained_stealth_path(self, ingress: str, target: str, attacker_tokens: list) -> list:
        logging.info(f"Filtering attack surface based on current token inventory...")
        pruned_graph = self.master_graph.copy()
        edges_to_remove = []
        
        for u, v, data in pruned_graph.edges(data=True):
            target_os = pruned_graph.nodes[v].get("operating_system", "Generic")
            required_os_family = data.get("required_os", "Any")
            required_token = data.get("required_token", "None")
            
            if required_os_family != "Any" and required_os_family not in target_os:
                edges_to_remove.append((u, v))
                continue
                
            if required_token != "None" and required_token not in attacker_tokens:
                edges_to_remove.append((u, v))

        pruned_graph.remove_edges_from(edges_to_remove)

        try:
            optimal_sequence = nx.dijkstra_path(pruned_graph, source=ingress, target=target, weight='weight')
            return optimal_sequence
        except nx.NetworkXNoPath:
            logging.warning("Zero valid stealthy routes exist under current token constraints.")
            return []
