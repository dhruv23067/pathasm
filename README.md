# pathasm: Context-Aware Graph Engineering for Stealth-Optimized Lateral Movement 

Project Overview:

PathAsm is an open-source, data-driven security engineering framework designed to automate the discovery, mapping, and simulation of post-exploitation lateral movement paths within enterprise environments. The project is currently in a highly stable prototype stage, with active development underway to transition the codebase into an industry-grade open-source security tool for formal public release. By analyzing internal network topologies through the lens of graph theory, the tool provides security teams and researchers with an intelligent platform to predict adversarial behavior and map hidden risks across complex corporate subnets post-breach.

Core Methodology & Innovation:

Traditional pathfinding models, such as basic shortest-path routines, optimize exclusively for infrastructure constraints like physical hop counts or raw network transmission speeds. PathAsm introduces an entirely new optimization paradigm for enterprise threat modeling by treating defensive logging density as an adversarial cost function to prioritize stealth. The framework dynamically scales the inherent execution risk of every connection against the active instrumentation profile of the target endpoint. By applying an optimization function that translates Endpoint Detection and Response monitoring severity into a formal routing cost, the pathfinder engine learns to avoid heavily audited segments in favor of less-monitored, context-validated alternatives. This allows the system to isolate routing trajectories that might utilize a higher number of structural steps but ultimately generate a dramatically lower network telemetry footprint.

System Architecture Blueprint:

The high-fidelity prototype is engineered with a strict decoupling between its data ingestion layer, constraint verification core, and visualization dashboard components. At the baseline, a structured schema maps out a complex twelve-node enterprise network encompassing dedicated edge networks, segmented corporate zones, administrative segments, and critical domain infrastructures. A dedicated topology parser ingests these multi-format asset metadata payloads and dynamically structures them into active Directed Graph matrices using Python's NetworkX library. To ensure the model reflects realistic operational scenarios, a secondary context engine acts as an adversarial constraint solver, systematically parsing current token inventories and destination operating platforms to prune unavailable attack paths prior to routing. The final optimization core executes unbuffered matrix calculations, passing the stealth-driven path coordinates straight into a standalone browser-based operations console dashboard powered by PyVis. Following the complete development of this industry-grade open-source toolkit, the framework will be fully ready for direct, scalable deployment within highly complex environments like production corporate networks to suggest quiet attack paths and identify critical weaknesses.

Framework In Action

1. The engine streams configuration from data/network_map.json, ingesting a graph topology consisting of 12 Assets (Vertices) and 13 Attack Vectors (Edges). Setting EXT-INTERNET as the ingress point and DC-PRIMARY-ION-01 as the high-value target asset, the pathfinder maps out a 5-pivot lateral movement sequence to minimize the logging footprint. It uses the mathematical formula below to calculate the telemetry cost:

Telemetry Weight = Base Attack Vector Risk x Destination EDR monitoring multiplier.

<img width="1479" height="369" alt="github1" src="https://github.com/user-attachments/assets/e1168fb5-c916-4093-9a1b-14e8d24abbdb" />

2. Following the execution trace calculation, the pipeline automatically processes the graph topology into a standalone, dark-themed interactive graph powered by `pyvis`. This browser-based dashboard translates complex numerical matrices into a live visual interface featuring dynamic physics clustering, flexible node layouts, and hover-over asset registries.

<img width="1799" height="851" alt="image" src="https://github.com/user-attachments/assets/5915cfa3-e171-486b-aef1-c8c428972a0a" />







