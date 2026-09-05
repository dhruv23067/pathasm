import os
import sys
import json
import logging
import networkx as nx

# Dynamically patch system execution paths to resolve subdirectory resolution bottlenecks
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class PathAsmTopologyIngestor:
    """
    Handles translation of enterprise network asset inventories and authorization
    metadata into formal Directed Graph matrices for automated path analysis.
    """
    def __init__(self, topology_data_path: str):
        self.data_path: str = topology_data_path
        self.graph: nx.DiGraph = nx.DiGraph()

    def parse_infrastructure(self) -> nx.DiGraph:
        logging.info(f"Streaming network telemetry configuration from source: {self.data_path}")
        
        try:
            with open(self.data_path, 'r') as file_stream:
                infrastructure_payload = json.load(file_stream)
        except (FileNotFoundError, json.JSONDecodeError) as error_context:
            logging.critical(f"Aborting ingestion: Failed to read asset topology metadata stream: {error_context}")
            return self.graph

        # Step 1: Parse and ingest vertices (Network Assets & Security Postures)
        for asset in infrastructure_payload.get("nodes", []):
            node_id = asset.get("id")
            if node_id:
                self.graph.add_node(
                    node_id,
                    asset_type=asset.get("type", "Unknown"),
                    operating_system=asset.get("os", "Generic"),
                    telemetry_multiplier=float(asset.get("edr_telemetry_cost", 1.0))
                )

        # Step 2: Parse and ingest directed edges (Exploitation and Pivot Vectors)
        for vector in infrastructure_payload.get("edges", []):
            src, dst = vector.get("source"), vector.get("target")
            
            # Defensive validation check: Ensure both assets exist in the graph matrix before link processing
            if src in self.graph and dst in self.graph:
                dst_telemetry_multiplier = self.graph.nodes[dst]["telemetry_multiplier"]
                
                # Math Core: Edge cost = base execution risk * destination monitoring weight
                calculated_detection_cost = float(vector.get("base_risk", 1.0)) * dst_telemetry_multiplier
                
                self.graph.add_edge(
                    src,
                    dst,
                    relationship=vector.get("relation", "NetworkAccess"),
                    weight=calculated_detection_cost
                )

        logging.info(f"Ingestion successful. Vertices (Assets): {self.graph.number_of_nodes()} | Edges (Attack Vectors): {self.graph.number_of_edges()}")
        return self.graph

if __name__ == "__main__":
    # Ingestion module isolated validation driver
    parser_instance = PathAsmTopologyIngestor("data/network_map.json")
    parser_instance.parse_infrastructure()
