import os
import sys
import logging
import networkx as nx
from pyvis.network import Network

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.ingestor import PathAsmTopologyIngestor
from src.engine_v2 import PathAsmContextEngine

logging.basicConfig(level=logging.INFO, format='%(asctime)s - [%(levelname)s] - %(message)s')

class PathAsmConsoleVisualizer:
    def __init__(self, target_graph: nx.DiGraph):
        self.graph = target_graph

    def render_operations_console(self, compromise_route: list = None, output_filename: str = "pathasm_console.html"):
        logging.info("Compiling PathAsm independent operations console dashboard...")
        
        net = Network(height="800px", width="100%", bgcolor="#0f1115", font_color="#e2e8f0", directed=True)
        
        path_edges = set()
        if compromise_route:
            path_edges = {(compromise_route[i], compromise_route[i+1]) for i in range(len(compromise_route)-1)}
        path_nodes = set(compromise_route) if compromise_route else set()

        for node, metadata in self.graph.nodes(data=True):
            role = metadata.get("asset_type", "Unknown")
            os_info = metadata.get("operating_system", "Generic")
            
            node_shape = "dot"
            node_size = 24
            
            if "Tier0" in role or role == "CrownJewel":
                node_color = "#ef4444"
                node_size = 34
            elif "Tier1" in role:
                node_color = "#f97316"
                node_size = 28
            elif "DMZ" in role:
                node_color = "#06b6d4"
            elif "External" in role:
                node_color = "#64748b"
            else:
                node_color = "#3b82f6"

            if node in path_nodes:
                border_color = "#ffffff"
                highlight_color = "#f43f5e"
                color_config = {"background": node_color, "border": border_color, "highlight": {"background": highlight_color, "border": "#ffffff"}}
            else:
                color_config = {"background": node_color, "border": "#1e293b", "highlight": {"background": node_color, "border": "#ffffff"}}

            properties_panel_html = f"""
            <div style='color: #cbd5e1; background-color: #1e293b; padding: 12px; border-radius: 6px; border: 1px solid #475569; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; font-size: 11px; line-height: 1.5;'>
                <span style='color: #38bdf8; font-weight: bold;'>⚙️ PATHASM ASSET METRIC REGISTER</span><br>
                <hr style='border-color: #334155; margin: 6px 0;'>
                <b>IDENTIFIER:</b> {node}<br>
                <b>ZONE CLASSIFICATION:</b> {role}<br>
                <b>OPERATING PLATFORM:</b> {os_info}<br>
                <b>TELEMETRY PROFILE:</b> {metadata.get('telemetry_multiplier', 1.0)}x EDR Cost Factor
            </div>
            """

            net.add_node(
                node, 
                label=node, 
                title=properties_panel_html, 
                color=color_config, 
                shape=node_shape, 
                size=node_size,
                borderWidth=2
            )

        for u, v, data in self.graph.edges(data=True):
            relationship = data.get("relationship", "Access")
            weight_cost = data.get("weight", 1.0)
            
            edge_color = "#334155"
            edge_width = 1.5
            
            if (u, v) in path_edges:
                edge_color = "#f43f5e"
                edge_width = 4.0

            net.add_edge(
                u, 
                v, 
                title=f"Exploit Vector: {relationship} | Weight Penalty Score: {weight_cost:.2f}", 
                label=relationship,
                color=edge_color, 
                width=edge_width,
                font={"size": 8, "color": "#94a3b8", "align": "middle"},
                smooth={"type": "horizontal", "roundness": 0.1}
            )

        net.set_options("""
        var options = {
          "physics": {
            "barnesHut": {
              "gravitationalConstant": -12000,
              "centralGravity": 0.15,
              "springLength": 160,
              "springStrength": 0.04,
              "damping": 0.16
            },
            "solver": "barnesHut",
            "stabilization": { "iterations": 200 }
          },
          "interaction": {
            "hover": true,
            "navigationButtons": true,
            "keyboard": true
          }
        }
        """)

        output_filepath = os.path.join(os.getcwd(), output_filename)
        net.write_html(output_filename)
        logging.info(f"Operations Console successfully compiled and written to: {output_filepath}")
        print(f"\n🖥️ PATHASM GRAPH UTILITY ONLINE. VISIT REGISTRY URL IN BROWSER:\n👉 file://{output_filepath}\n")

if __name__ == "__main__":
    loader = PathAsmTopologyIngestor("data/network_map.json")
    graph = loader.parse_infrastructure()
    
    engine = PathAsmContextEngine(graph)
    stolen_artifacts = ["SSH_Priv_Key", "SQL_Admin_Creds", "Local_Admin_Token", "Domain_Admin_Creds"]
    
    calculated_path = engine.compute_constrained_stealth_path(
        ingress="EXT-INTERNET", 
        target="DC-PRIMARY-01", 
        attacker_tokens=stolen_artifacts
    )
    
    viz = PathAsmConsoleVisualizer(graph)
    viz.render_operations_console(compromise_route=calculated_path)


