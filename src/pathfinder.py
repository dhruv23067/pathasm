import os
import sys
import logging
import networkx as nx

# Dynamically patch system execution paths to resolve subdirectory resolution bottlenecks
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.ingestor import PathAsmTopologyIngestor

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class PathAsmEngine:
    """
    Evaluates state-space infrastructure topologies to isolate optimal, 
    low-telemetry attack paths minimizing EDR defensive friction.
    """
    def __init__(self, topology_graph: nx.DiGraph):
        self.graph = topology_graph

    def compute_stealth_path(self, ingress: str, target: str) -> list:
        if ingress not in self.graph or target not in self.graph:
            logging.error(f"Routing boundary violation: Node markers '{ingress}' or '{target}' absent from topology matrix.")
            return []

        logging.info(f"Computing dynamic edge metrics from entry point [{ingress}] to target asset [{target}]...")
        
        try:
            # Dijkstra routing matrix computation optimized for EDR detection costs
            optimal_sequence = nx.dijkstra_path(self.graph, source=ingress, target=target, weight='weight')
            cumulative_cost = nx.dijkstra_path_length(self.graph, source=ingress, target=target, weight='weight')
            
            self._print_execution_matrix(optimal_sequence, cumulative_cost)
            return optimal_sequence
            
        except nx.NetworkXNoPath:
            logging.warning(f"Path verification failed: Segment containment verified between {ingress} and {target}.")
            return []

    def _print_execution_matrix(self, computed_path: list, total_cost: float):
        print(f"\n" + "="*75)
        print(f"🔹 PATHASM ROUTING MODEL COMPUTE SUCCESSFUL")
        print(f"="*75)
        print(f"[*] Target Pivot Line:  {' -> '.join(computed_path)}")
        print(f"[*] Cumulative Detection Cost Metric: {total_cost:.2f}")
        print(f"---------------------------------------------------------------------------")
        
        for idx in range(len(computed_path) - 1):
            u, v = computed_path[idx], computed_path[idx + 1]
            edge_data = self.graph[u][v]
            print(f"    Pivot {idx+1}: {u} -> {v} via [{edge_data['relationship']}] (Telemetry Cost: {edge_data['weight']:.2f})")
        print(f"="*75 + "\n")

if __name__ == "__main__":
    # Ingestion driver initialization pointing to our expanded 12-node topology dataset
    loader = PathAsmTopologyIngestor("data/network_map.json")
    active_graph = loader.parse_infrastructure()
    
    if active_graph.number_of_nodes() == 0:
        logging.critical("Graph initialization matrix is empty. Terminating engine execution pipeline.")
        sys.exit(1)
        
    engine = PathAsmEngine(active_graph)
    
    # Executing the math routine using our new high-fidelity blueprint endpoints
    engine.compute_stealth_path(ingress="EXT-INTERNET", target="DC-PRIMARY-01")
