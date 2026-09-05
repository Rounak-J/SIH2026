import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
import os
from datetime import datetime

from scanner import CryptoScanner
from risk_engine import evaluate_finding, evaluate_mosca
from cbom_generator import generate_cyclonedx, generate_pdf_report
from network_scanner import NetworkScanner

st.set_page_config(
    page_title="S.Q.A.N.", 
    page_icon="assets/logo.png", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for Deep Enterprise Polish
st.markdown("""
<style>
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stAppDeployButton {display:none !important;}
    header {visibility: hidden;}
    
    .block-container {
        padding-top: 3rem;
        padding-bottom: 2rem;
    }
    
    div[data-testid="metric-container"] {
        background-color: #12141c;
        border: 1px solid #1f2330;
        padding: 1.2rem;
        border-radius: 0.25rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
    }
    
    div[data-testid="stMetricDelta"] svg {
        display: none;
    }
    
    h1, h2, h3, h4, h5 {
        font-family: 'Inter', sans-serif;
        font-weight: 500 !important;
        letter-spacing: -0.02em;
        color: #f8f9fa;
    }
    
    .stMarkdown p, .stMarkdown span {
        font-family: 'Inter', sans-serif;
        color: #a0aec0;
    }
    
    .stButton button {
        background-color: #4A90E2 !important;
        border: none !important;
    }
    .stButton button p {
        color: #ffffff !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px;
    }
    </style>
    """, unsafe_allow_html=True)

if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'scan_completed' not in st.session_state:
    st.session_state['scan_completed'] = False
if 'mosca_x' not in st.session_state:
    st.session_state['mosca_x'] = 10
if 'mosca_y' not in st.session_state:
    st.session_state['mosca_y'] = 3
if 'mosca_z' not in st.session_state:
    st.session_state['mosca_z'] = 7

# LOGIN
if not st.session_state['authenticated']:
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<div style='margin-top: 5vh;'></div>", unsafe_allow_html=True)
        with st.container(border=True):
            c_logo1, c_logo2, c_logo3 = st.columns([1, 0.8, 1])
            with c_logo2:
                try:
                    st.image("assets/logo.png", use_container_width=True)
                except:
                    pass
            
            st.markdown("<h2 style='text-align: center; margin-bottom: 0; color: #fff;'>S.Q.A.N.</h2>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; font-size: 0.8em; margin-top: 0; letter-spacing: 2px; color: #00d2ff;'>SCALABLE QUANTUM ARTEFACT NAVIGATOR</p>", unsafe_allow_html=True)
            st.divider()
            
            with st.form("login_form", clear_on_submit=False):
                username = st.text_input("OPERATOR ID", placeholder="admin")
                password = st.text_input("PASSCODE", type="password", placeholder="••••••••")
                submitted = st.form_submit_button("AUTHENTICATE SESSION", use_container_width=True)
                
                if submitted:
                    if username == "admin" and password == "ntro2026":
                        st.session_state['authenticated'] = True
                        st.rerun()
                    else:
                        st.error("ACCESS DENIED: Invalid Credentials.")
            
            st.markdown("<p style='text-align: center; color: #444; font-size: 0.7rem; margin-top: 1rem; letter-spacing: 1px;'>RESTRICTED SYSTEM. ALL ATTEMPTS ARE LOGGED.</p>", unsafe_allow_html=True)

else:
    # SIDEBAR
    with st.sidebar:
        try:
            st.image("assets/logo.png", width=120)
        except:
            pass
        st.markdown("### SQAN ")
        st.caption("ENTERPRISE EDITION v2.4.1 | BUILD 8942")
        st.divider()
        
        st.markdown("**OPERATOR:** ADMIN (LEVEL 5)")
        st.markdown("**NODE:** IND-DEL-01")
        st.markdown(f"**SESSION:** {datetime.now().strftime('%H:%M')} IST")
        
        st.divider()
        menu_selection = st.radio("NAVIGATION", 
            ["OVERVIEW DASHBOARD", "CBOM INVENTORY", "VULNERABILITY REPORTS", "SYSTEM SETTINGS"],
            label_visibility="collapsed"
        )
        st.divider()
        
        if st.button("TERMINATE SESSION", use_container_width=True):
            st.session_state['authenticated'] = False
            st.session_state['scan_completed'] = False
            st.rerun()

    # DASHBOARD
    if menu_selection == "OVERVIEW DASHBOARD":
        col_header1, col_header2 = st.columns([3, 1])
        with col_header1:
            st.header("Executive Quantum Risk Dashboard")
            st.markdown("Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)")
        with col_header2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.session_state.get('scan_completed', False):
                try:
                    with open("executive_audit.pdf", "rb") as f:
                        st.download_button("EXPORT PDF REPORT", f, file_name="executive_audit.pdf", use_container_width=True)
                except:
                    pass
                
        st.divider()
        with st.container(border=True):
            st.markdown("##### Scan Configuration")
            
            t_col1, t_col2 = st.columns(2)
            with t_col1: target_type = st.radio("TARGET TYPE", ["Local Codebase", "Live Network URL"], horizontal=True, label_visibility="collapsed")
            with t_col2: 
                if target_type == "Local Codebase":
                    scan_mode = st.selectbox("ANALYSIS MODE", ["DEEP AST", "FAST REGEX", "BINARY ANALYSIS"], label_visibility="collapsed")
                else:
                    st.selectbox("ANALYSIS MODE", ["NETWORK TLS PROBE"], disabled=True, label_visibility="collapsed")
                    scan_mode = "NETWORK TLS PROBE"
                    
            c_col1, c_col2 = st.columns(2)
            with c_col1: criticality = st.selectbox("BUSINESS CRITICALITY", ["Internal / Low Risk", "Core Operational", "Mission Critical"], label_visibility="collapsed")
            with c_col2: compliance = st.selectbox("COMPLIANCE STANDARD", ["Standard Industry Baseline", "NSA CNSA 2.0 (Military Grade)"], label_visibility="collapsed")
            
            p_col1, p_col2 = st.columns([4, 1])
            with p_col1:
                if target_type == "Local Codebase":
                    target_dir = st.text_input("TARGET PATH", value=os.path.abspath("dummy_repo"), label_visibility="collapsed")
                else:
                    target_dir = st.text_input("NETWORK URL", value="google.com", label_visibility="collapsed")
            with p_col2:
                run_scan = st.button("EXECUTE SCAN", use_container_width=True)
                
        if run_scan:
            with st.spinner("Initializing analysis engines..."):
                time.sleep(1)
                
                # Save criticality for the Mosca Simulator
                st.session_state['criticality'] = criticality
                
                if target_type == "Local Codebase":
                    scanner = CryptoScanner(mode=scan_mode)
                    raw_findings = scanner.scan_directory(target_dir)
                else:
                    net_scanner = NetworkScanner()
                    raw_findings = net_scanner.scan_url(target_dir)
                
                enriched_findings = []
                for f in raw_findings:
                    eval_data = evaluate_finding(f['artefact'], compliance_mode=compliance)
                    f['risk'] = eval_data['risk']
                    f['remediation'] = eval_data['remediation']
                    enriched_findings.append({
                        "FILE PATH": f"{os.path.basename(f['file_path'])} (Line {f['line_number']})",
                        "ARTEFACT": f['artefact'],
                        "TYPE": f['type'],
                        "RISK LEVEL": f['risk'],
                        "REMEDIATION STRATEGY": f['remediation']
                    })
                
                generate_cyclonedx(raw_findings, "cyclonedx_cbom.json")
                try:
                    generate_pdf_report(raw_findings, "executive_audit.pdf")
                except: pass
                
                st.session_state['enriched_findings'] = enriched_findings
                st.session_state['raw_findings'] = raw_findings
                st.session_state['scan_completed'] = True
                
                # Force update the Mosca simulator inputs based on new findings!
                critical_risk_count = sum(1 for f in enriched_findings if f['RISK LEVEL'] in ['Critical', 'High'])
                has_asym = any(f['TYPE'] == 'Asymmetric Key Exchange' for f in enriched_findings)
                st.session_state['mosca_y'] = min(15, 1 + int(0.5 * critical_risk_count))
                
                # Apply Business Criticality modifier to Shelf Life (X)
                base_x = 15 if has_asym else 5
                criticality_val = st.session_state.get('criticality', 'Internal / Low Risk')
                if criticality_val == 'Mission Critical':
                    base_x += 5
                elif criticality_val == 'Core Operational':
                    base_x += 2
                    
                st.session_state['mosca_x'] = base_x

        if st.session_state.get('scan_completed', False):
            enriched_findings = st.session_state.get('enriched_findings', [])
            total_artefacts = len(enriched_findings)
            critical_risk = sum(1 for f in enriched_findings if f['RISK LEVEL'] in ['Critical', 'High'])
            medium_risk = sum(1 for f in enriched_findings if f['RISK LEVEL'] == 'Medium')
            safe = sum(1 for f in enriched_findings if f['RISK LEVEL'] == 'Safe')
            
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("### Risk Telemetry")
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("TOTAL ARTEFACTS", str(total_artefacts))
            m2.metric("CRITICAL RISK", str(critical_risk), delta_color="inverse")
            m3.metric("MEDIUM RISK", str(medium_risk), delta_color="off")
            m4.metric("PQC COMPLIANT", str(safe), delta_color="normal")
            
            st.markdown("<br>", unsafe_allow_html=True)
            col_chart1, col_chart2 = st.columns([1, 1.2])
            with col_chart1:
                with st.container(border=True):
                    st.markdown("##### Cryptographic Algorithm Distribution")
                    dist = {}
                    for f in enriched_findings: dist[f['ARTEFACT']] = dist.get(f['ARTEFACT'], 0) + 1
                    labels = list(dist.keys()) if dist else ['None']
                    values = list(dist.values()) if dist else [1]
                    fig_donut = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.65, textinfo='label+percent')])
                    fig_donut.update_layout(margin=dict(t=10, b=10, l=10, r=10), height=220, showlegend=False, paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color="#a0aec0"))
                    st.plotly_chart(fig_donut, use_container_width=True, config={'displayModeBar': False})
            
            with col_chart2:
                with st.container(border=True):
                    st.markdown("##### Mosca's Risk Simulator (X + Y > Z)")
                    
                    x_val = st.session_state['mosca_x']
                    y_val = st.session_state['mosca_y']
                    z_val = st.session_state['mosca_z']
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("SHELF-LIFE (X)", f"{x_val} yrs")
                    c2.metric("MIGRATION (Y)", f"{y_val} yrs")
                    c3.metric("Q-DAY HORIZON (Z)", f"{z_val} yrs")
                    
                    is_danger, exposure = evaluate_mosca(x_val, y_val, z_val)
                    total_time = x_val + y_val
                    if is_danger: st.error(f"CRITICAL EXPOSURE: X + Y ({total_time} yrs) > Z ({z_val} yrs) [Window: {exposure}y]")
                    else: st.success(f"SECURE: X + Y ({total_time} yrs) ≤ Z ({z_val} yrs)")

            st.divider()
            
            # --- Visual Threat Graph ---
            st.markdown("### Visual Threat Topology")
            if len(enriched_findings) > 0:
                dot = "digraph {\n"
                dot += 'node [shape=box, style=filled, color="#2E3A59", fontcolor=white, fontname="Helvetica"];\n'
                dot += 'edge [color="#6B7280"];\n'
                dot += 'rankdir=LR;\n'
                
                added_nodes = set()
                for f in enriched_findings:
                    fpath = f['FILE PATH'].split('/')[-1].split('\\')[-1]
                    vuln = f['ARTEFACT']
                    risk = f['RISK LEVEL']
                    
                    if fpath not in added_nodes:
                        dot += f'"{fpath}" [shape=note, color="#374151"];\n'
                        added_nodes.add(fpath)
                    if vuln not in added_nodes:
                        color = "#EF4444" if risk == "Critical" else "#F59E0B" if risk == "High" else "#10B981" if risk == "Safe" else "#3B82F6"
                        dot += f'"{vuln}" [color="{color}"];\n'
                        added_nodes.add(vuln)
                    
                    dot += f'"{fpath}" -> "{vuln}";\n'
                dot += "}"
                
                st.graphviz_chart(dot)
            else:
                st.info("No threats to visualize.")
                
            st.divider()
            st.markdown("### Critical Discoveries")
            df = pd.DataFrame(enriched_findings)
            def color_risk(val):
                if val == 'Critical': return 'color: #EF4444; font-weight: 600'
                elif val == 'High': return 'color: #F87171; font-weight: 600'
                elif val == 'Medium': return 'color: #FBBF24; font-weight: 600'
                elif val == 'Safe': return 'color: #10B981; font-weight: 600'
                return ''
            
            if not df.empty:
                try:
                    styled_df = df.style.map(color_risk, subset=['RISK LEVEL'])
                    st.dataframe(styled_df, use_container_width=True, hide_index=True)
                except AttributeError:
                    styled_df = df.style.applymap(color_risk, subset=['RISK LEVEL'])
                    st.dataframe(styled_df, use_container_width=True, hide_index=True)
            else:
                st.info("No cryptographic artefacts found in the target directory.")

    elif menu_selection == "CBOM INVENTORY":
        st.header("CBOM Inventory Archive")
        st.markdown("This module centralizes all historically generated Cryptographic Bills of Materials across the enterprise.")
        if st.session_state.get('scan_completed', False):
            st.success("Latest scan data is available.")
            try:
                with open("cyclonedx_cbom.json", "r") as f:
                    cbom_json = f.read()
                st.download_button("📥 Download Latest CycloneDX CBOM (JSON)", cbom_json, file_name="cyclonedx_cbom.json", use_container_width=True)
                with st.expander("View Raw JSON Dump"):
                    st.code(cbom_json, language="json")
            except:
                st.error("CBOM file not found. Please run a scan first.")
        else:
            st.warning("No scans executed in current session. Run a scan from the Overview Dashboard to populate the inventory.")

    elif menu_selection == "VULNERABILITY REPORTS":
        st.header("Executive Vulnerability Reports")
        st.markdown("View static PDFs and historical trend lines for quantum cryptographic exposure.")
        if st.session_state.get('scan_completed', False):
            try:
                with open("executive_audit.pdf", "rb") as f:
                    st.download_button("📥 Download Executive Audit (PDF)", f, file_name="executive_audit.pdf", use_container_width=True)
            except FileNotFoundError:
                st.error("Audit report not found.")
        else:
            st.warning("No reports available. Run a scan from the Overview Dashboard.")

    elif menu_selection == "SYSTEM SETTINGS":
        st.header("Core Engine Settings")
        st.markdown("Adjust scanning guardrails and deep analysis configurations.")
        with st.form("settings_form"):
            st.slider("Max AST Depth limit", 1, 100, 25)
            st.checkbox("Enable Heuristic Analysis (Slower but more accurate)", value=True)
            st.text_input("Custom Ignore Regex", value="(node_modules|vendor|\.git)")
            st.form_submit_button("Save Configurations")