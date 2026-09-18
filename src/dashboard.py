import streamlit as st
import json
import os
import networkx as nx
import io
import logging
from pyvis.network import Network
import streamlit.components.v1 as components
from engine import PathAsmCoreEngine

logging.getLogger("pydantic").setLevel(logging.ERROR)

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

st.set_page_config(
    page_title="PATHASM // CORE TACTICAL INTERFACE", 
    page_icon="🥷", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

st.markdown("""
    <style>
        @import url('https://googleapis.com');
        html, body, [data-testid="stAppViewContainer"], [data-testid="stHeader"] { background-color: #05070B !important; color: #FFFFFF !important; font-family: 'JetBrains Mono', monospace !important; }
        .title-header { color: #00FFCC !important; font-size: 2.8rem !important; font-weight: 800 !important; letter-spacing: 0.5px; text-shadow: 0 0 25px rgba(0, 255, 204, 0.6), 0 0 50px rgba(0, 255, 204, 0.2); margin-top: 10px !important; margin-bottom: 5px !important; }
        .subtitle-header { color: #0099FF !important; font-size: 1.3rem !important; font-weight: 600 !important; text-shadow: 0 0 15px rgba(0, 153, 255, 0.4); margin-bottom: 35px !important; letter-spacing: 0.5px; }
        label, .stSelectbox label, .stRadio label, div[data-testid="stWidgetLabel"] p { color: #00FFCC !important; font-size: 1.2rem !important; font-weight: 700 !important; letter-spacing: 1px !important; text-transform: uppercase !important; text-shadow: 0 0 10px rgba(0, 255, 204, 0.3); margin-bottom: 8px !important; }
        div[data-baseweb="select"] { background-color: #0E131F !important; border: 2px solid #1E293B !important; border-radius: 8px !important; }
        div[data-baseweb="select"] * { color: #FFFFFF !important; font-size: 1.1rem !important; font-weight: 600 !important; }
        .metric-card-custom { background: linear-gradient(145deg, #0D111A 0%, #151B26 100%); border-radius: 16px; padding: 30px; border: 2px solid #1E293B; box-shadow: 0 15px 35px rgba(0, 0, 0, 0.6); margin-bottom: 25px; min-height: 220px; }
        .metric-card-custom.shortest { border: 2px solid #FF0055; box-shadow: 0 0 25px rgba(255, 0, 85, 0.15); }
        .metric-card-custom.stealth { border: 2px solid #00FFCC; box-shadow: 0 0 25px rgba(0, 255, 204, 0.15); }
        .metric-card-title { color: #FFFFFF !important; font-size: 1.1rem !important; font-weight: 700 !important; letter-spacing: 2px; margin-bottom: 12px; text-transform: uppercase; }
        .shortest .metric-card-title { color: #FF0055 !important; text-shadow: 0 0 10px rgba(255, 0, 85, 0.4); }
        .stealth .metric-card-title { color: #00FFCC !important; text-shadow: 0 0 10px rgba(0, 255, 204, 0.4); }
        .metric-card-value { font-size: 3.2rem !important; font-weight: 800 !important; line-height: 1.1 !important; margin-bottom: 12px; letter-spacing: -0.5px; }
        .shortest .metric-card-value { color: #FF0055 !important; text-shadow: 0 0 20px rgba(255, 0, 85, 0.5); }
        .stealth .metric-card-value { color: #00FFCC !important; text-shadow: 0 0 20px rgba(0, 255, 204, 0.5); }
        .metric-card-delta { color: #FFFFFF !important; font-size: 1.2rem !important; font-weight: 700 !important; margin-bottom: 18px; letter-spacing: 0.5px; }
        .trace-box { background: #06080D !important; padding: 12px 16px !important; border-radius: 8px !important; border: 2px solid #1E293B !important; font-size: 1rem !important; font-weight: 600 !important; overflow-x: auto; white-space: nowrap; }
        section[data-testid="stSidebar"] { background-color: #07090E !important; border-right: 2px solid #1E293B !important; }
        .stButton>button { background: linear-gradient(90deg, #00FFCC 0%, #0099FF 100%) !important; color: #05070B !important; font-size: 1.1rem !important; font-weight: 800 !important; letter-spacing: 1px !important; border: none !important; border-radius: 8px !important; padding: 14px 24px !important; width: 100% !important; transition: all 0.3s ease !important; box-shadow: 0 0 20px rgba(0, 255, 204, 0.4) !important; }
        .stButton>button:hover { transform: translateY(-3px) !important; box-shadow: 0 0 35px rgba(0, 255, 204, 0.7) !important; }
    </style>
""", unsafe_allow_html=True)
st.markdown('<div class="title-header">🥷 PATHASM // THREAT CONTROL CENTER</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle-header">CONTEXT-AWARE MATRIX ROUTING ENGINE & TELEMETRY EVASION SOLVER</div>', unsafe_allow_html=True)
st.sidebar.markdown("<h2 style='color: #00FFCC; font-size: 1.5rem; font-weight: 800; letter-spacing: 1.5px; text-shadow: 0 0 15px rgba(0,255,204,0.4); margin-bottom: 25px;'>DATA FILE CONTROLS</h2>", unsafe_allow_html=True)

preload_path = os.environ.get("PATHASM_PRELOAD_FILE")
ad_data = None

if preload_path and os.path.exists(preload_path):
    st.sidebar.success(f"📦 Preloaded via CLI: {os.path.basename(preload_path)}")
    if st.sidebar.button("Clear Preloaded Data"):
        if "PATHASM_PRELOAD_FILE" in os.environ:
            del os.environ["PATHASM_PRELOAD_FILE"]
        st.rerun()
    try:
        with open(preload_path, "r", encoding="utf-8") as f:
            ad_data = json.load(f)
    except Exception as e:
        st.sidebar.error(f"Failed parsing preloaded mapping profile: {e}")
else:
    uploaded_file = st.sidebar.file_uploader("UPLOAD ACTIVE DIRECTORY BLUEPRINT (.ZIP / .JSON)", type=["json", "zip"])
    if uploaded_file is not None:
        file_name = uploaded_file.name.lower()
        if file_name.endswith('.zip'):
            import zipfile
            ad_data = {"data": [], "meta": {"type": "combined", "count": 0}}
            try:
                with zipfile.ZipFile(uploaded_file, 'r') as archive:
                    for arch_file in archive.namelist():
                        arch_file_lower = arch_file.lower()
                        if arch_file_lower.endswith(('users.json', 'computers.json', 'groups.json')):
                            try:
                                file_content = json.loads(archive.read(arch_file))
                                extracted_records = file_content.get("data", [])
                                ad_data["data"].extend(extracted_records)
                            except Exception as parse_err:
                                st.sidebar.warning(f"Skipped parsing artifact {arch_file}: {parse_err}")
                ad_data["meta"]["count"] = len(ad_data["data"])
                if ad_data["meta"]["count"] > 0:
                    st.sidebar.success(f"📦 Successfully parsed compressed matrix bundle ({ad_data['meta']['count']} entities found)")
                else:
                    st.sidebar.error("The uploaded zip archive does not contain valid SharpHound JSON exports.")
                    ad_data = None
            except Exception as zip_err:
                st.sidebar.error(f"Archive Extractor Exception: Failed to decode zip payload. Details: {zip_err}")
                ad_data = None
        else:
            try:
                ad_data = json.load(uploaded_file)
            except Exception as e:
                st.sidebar.error(f"Data Schema Parsing Exception: Invalid JSON. Details: {e}")
                ad_data = None

def compile_professional_pdf(shortest_res, stealth_res, src, dst, selected_mode):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontName='Helvetica-Bold', fontSize=22, textColor=colors.HexColor("#111827"), spaceAfter=15)
    h2_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontName='Helvetica-Bold', fontSize=13, textColor=colors.HexColor("#1F2937"), spaceBefore=15, spaceAfter=8)
    body_style = ParagraphStyle('ReportBody', parent=styles['ReportBody'] if 'ReportBody' in styles else styles['BodyText'], fontName='Helvetica', fontSize=10, leading=14, textColor=colors.HexColor("#4B5563"))
    story = [
        Paragraph("PathAsm Strategic Assessment Briefing", title_style),
        Paragraph("<b>Classification:</b> Operational Security Data (Internal Penetration Testing Team)", body_style),
        Spacer(1, 12)
    ]
    meta_table_data = [
        [Paragraph("<b>Origin Vector Entry Point:</b>", body_style), Paragraph(src, body_style)],
        [Paragraph("<b>Target Objective Destination:</b>", body_style), Paragraph(dst, body_style)],
        [Paragraph("<b>Active Interface Mapping Target:</b>", body_style), Paragraph(selected_mode, body_style)]
    ]
    t_meta = Table(meta_table_data, colWidths=[200, 300])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F9FAFB")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 15))
    story.append(Paragraph("Comparative Routing Metrics Table", h2_style))
    metrics_table_data = [
        [Paragraph("<b>Evaluated Dimension</b>", body_style), Paragraph("<b>Strategy A: Shortest Path</b>", body_style), Paragraph("<b>Strategy B: Stealthiest Path</b>", body_style)],
        [Paragraph("Total Infrastructure Hops", body_style), Paragraph(str(shortest_res.get('total_hops', 'N/A')), body_style), Paragraph(str(stealth_res.get('total_hops', 'N/A')), body_style)],
        [Paragraph("Accumulated Telemetry Penalty", body_style), Paragraph(str(shortest_res.get('accumulated_telemetry_penalty', 'N/A')), body_style), Paragraph(str(stealth_res.get('accumulated_telemetry_penalty', 'N/A')), body_style)]
    ]
    t_metrics = Table(metrics_table_data, colWidths=[160, 170, 170])
    t_metrics.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F3F4F6")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#D1D5DB")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
    ]))
    story.append(t_metrics)
    story.append(Spacer(1, 15))
    sh_path = " ➔ ".join(shortest_res.get('route', [])) if 'route' in shortest_res else "No Path Found"
    st_path = " ➔ ".join(stealth_res.get('route', [])) if 'route' in stealth_res else "No Path Found"
    story.append(Paragraph("Calculated Network Trajectories", h2_style))
    story.append(Paragraph(f"<b>Shortest Structural Pathway:</b><br/>{sh_path}", body_style))
    story.append(Spacer(1, 10))
    story.append(Paragraph(f"<b>Telemetry-Aware Evasion Pathway:</b><br/><b>{st_path}</b>", body_style))
    story.append(Spacer(1, 35))
    story.append(Paragraph("<font size=7.5 color='#9CA3AF'>Report compiled automatically via PathAsm Graph Solver Platform Core Engine.</font>", body_style))
    doc.build(story)
    buffer.seek(0)
    return buffer.getvalue()
if ad_data is not None:
    try:
        engine = PathAsmCoreEngine(ad_data)
        all_nodes = sorted(list(engine.graph.nodes))
        st.sidebar.markdown("<h2 style='color: #00FFCC; font-size: 1.5rem; font-weight: 800; letter-spacing: 1.5px; text-shadow: 0 0 15px rgba(0,255,204,0.4); margin-bottom: 25px;'>CONSTRAINTS CORE</h2>", unsafe_allow_html=True)
        
        source_node = st.sidebar.selectbox("COMPROMISED ORIGIN VECTOR (SOURCE):", all_nodes, index=0)
        
        dc_targets = [n for n in all_nodes if any(k in n.lower() for k in ["dc0", "dc1", "domain admin", "krbtgt", "administrator"])]
        if dc_targets:
            default_target_idx = all_nodes.index(dc_targets[0])
        else:
            default_target_idx = len(all_nodes) - 1 if all_nodes else 0
            
        target_node = st.sidebar.selectbox("HIGH VALUE TARGET (DESTINATION):", all_nodes, index=default_target_idx)
        routing_strategy = st.sidebar.radio("OPTIMIZATION CORE TARGET:", ["Stealthiest Route (Evasion Focus)", "Shortest Route (Hop Focus)"])
        
        analysis = engine.calculate_adversarial_routes(source_node, target_node)
        chosen_route = []
        
        if "error" in analysis:
            st.sidebar.error(f"Routing Matrix Exception: {analysis['error']}")
        else:
            shortest_res = analysis["shortest_path"]
            stealth_res = analysis["stealthiest_path"]
            
            if "error" in shortest_res or "error" in stealth_res:
                st.markdown("<div style='background-color: rgba(255, 0, 85, 0.15); border: 2px solid #FF0055; padding: 22px; border-radius: 12px; color: #FFD2E0; font-weight: bold; font-size: 1.2rem; text-shadow: 0 0 10px rgba(255,0,85,0.3); text-transform: uppercase;'>⚠️ BOUNDARY UNREACHABLE: Target objective isolation prevents cross-segment authentication propagation.</div>", unsafe_allow_html=True)
            else:
                chosen_route = stealth_res["route"] if "Stealthiest" in routing_strategy else shortest_res["route"]
                m_col1, m_col2 = st.columns(2)
                with m_col1:
                    st.markdown(f"""
                        <div class="metric-card-custom shortest">
                            <div class="metric-card-title">🔴 STRATEGY A // HOPS FOCUS</div>
                            <div class="metric-card-value">{shortest_res['accumulated_telemetry_penalty']} STEALTH RATING</div>
                            <div class="metric-card-delta">💥 {shortest_res['total_hops']} HOPS DETECTED IN ROUTE</div>
                            <div class="trace-box"><code style="color: #FF0055;">{' ➔ '.join(shortest_res['route'])}</code></div>
                        </div>
                    """, unsafe_allow_html=True)
                with m_col2:
                    st.markdown(f"""
                        <div class="metric-card-custom stealth">
                            <div class="metric-card-title">🟢 STRATEGY B // EVASION METRIC SEARCH</div>
                            <div class="metric-card-value">{stealth_res['accumulated_telemetry_penalty']} STEALTH RATING</div>
                            <div class="metric-card-delta">🛡️ {stealth_res['total_hops']} HOPS DETECTED IN ROUTE</div>
                            <div class="trace-box"><code style="color: #00FFCC;">{' ➔ '.join(stealth_res['route'])}</code></div>
                        </div>
                    """, unsafe_allow_html=True)
                    
        st.markdown("<br>", unsafe_allow_html=True)
        net = Network(height="590px", width="100%", bgcolor="#05070B", font_color="#FFFFFF", directed=True)
        
        visible_nodes = set(chosen_route)
        if len(chosen_route) > 0:
            for node in chosen_route:
                visible_nodes.update(engine.graph.predecessors(node))
                visible_nodes.update(engine.graph.successors(node))
        else:
            visible_nodes.update([source_node, target_node])
            
        MAX_DISPLAY_LIMIT = 300
        render_nodes = list(visible_nodes)[:MAX_DISPLAY_LIMIT]
        
        for node_id in render_nodes:
            if not engine.graph.has_node(node_id): continue
            node_color = "#00FFCC" if node_id in chosen_route else "#1E293B"
            if node_id == source_node: node_color = "#FF0055"
            elif node_id == target_node: node_color = "#F59E0B"
            net.add_node(node_id, label=node_id.upper(), title=f"Principal ID: {node_id}", color=node_color, size=30 if (node_id == source_node or node_id == target_node) else (24 if node_id in chosen_route else 14))
            
        for u, v, edata in engine.graph.edges(data=True):
            if u in render_nodes and v in render_nodes:
                is_link_on_path = False
                if len(chosen_route) > 1:
                    for i in range(len(chosen_route) - 1):
                        if (chosen_route[i] == u and chosen_route[i+1] == v) or (chosen_route[i] == v and chosen_route[i+1] == u):
                            is_link_on_path = True
                            break
                edge_color = "#00FFCC" if is_link_on_path else "#1E293B"
                net.add_edge(u, v, title=f"Exploit Payload: {edata.get('rule_id', edata.get('type', 'ALLOW'))}", color=edge_color, width=4.5 if is_link_on_path else 1.5, arrows="to")
                
        try:
            net.save_graph("temp_graph.html")
            with open("temp_graph.html", "r", encoding="utf-8") as f:
                html_markup = f.read()
            st.markdown("<div style='border: 2px solid #1E293B; border-radius: 16px; overflow: hidden; box-shadow: 0 25px 50px rgba(0,0,0,0.8);'>", unsafe_allow_html=True)
            components.html(html_markup, height=600)
            st.markdown("</div>", unsafe_allow_html=True)
            st.sidebar.markdown("<br><h3 style='color: #64748B; font-size: 1rem; font-weight:700; text-transform: uppercase; letter-spacing: 1.5px;'>COMPLIANCE EXPORTS</h3>", unsafe_allow_html=True)
            st.sidebar.download_button(label="🌐 EXPORT GRAPH MATRIX (.HTML)", data=html_markup, file_name=f"pathasm_matrix_{source_node}_to_{target_node}.html", mime="text/html", use_container_width=True)
            if REPORTLAB_AVAILABLE and "error" not in analysis and ("shortest_path" in analysis and "error" not in analysis["shortest_path"]):
                pdf_payload = compile_professional_pdf(shortest_res, stealth_res, source_node, target_node, routing_strategy)
                st.sidebar.download_button(label="📄 COMPILE BRIEFING DATA (.PDF)", data=pdf_payload, file_name=f"pathasm_assessment_{source_node}_to_{target_node}.pdf", mime="application/pdf", use_container_width=True)
            if os.path.exists("temp_graph.html"): os.remove("temp_graph.html")
        except Exception as e: st.error(f"Visual Matrix Processing Interruption: {e}")
    except Exception as general_err: st.error(f"Engine Computational Interruption: Data structure processing failed. Details: {general_err}")
else:
    st.markdown("""
        <div style='background: linear-gradient(145deg, #0D111A 0%, #151B26 100%); border: 2px solid #1E293B; border-radius: 16px; padding: 40px; text-align: center; box-shadow: 0 15px 35px rgba(0,0,0,0.6); margin-top: 50px;'>
            <h3 style='color: #00FFCC; font-size: 1.5rem; font-weight: 800; letter-spacing: 1px; margin-bottom: 15px;'>🛰️ AWAITING TARGET OPERATIONAL LANDSCAPE INPUT</h3>
            <p style='color: #9CA3AF; font-size: 1.1rem; line-height: 1.6; max-width: 700px; margin: 0 auto 25px auto;'>
                No Active Directory environment profile has been loaded. Drop a standard domain infrastructure JSON map profiling dataset or a raw <b>SharpHound database file export</b> into the left control deck panel to calculate tactical routing paths.
            </p>
            <div style='color: #0099FF; font-family: monospace; font-size: 0.95rem; font-weight: 700; letter-spacing: 0.5px;'>
                [ STATUS: THREAT CONTROL MODULE STANDBY // DEPLOYMENT ENGINE IDLE ]
            </div>
        </div>
    """, unsafe_allow_html=True)
