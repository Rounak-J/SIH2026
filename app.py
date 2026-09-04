import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import time
from datetime import datetime

# 1. Page Configuration
st.set_page_config(
    page_title="S.Q.A.N.", 
    page_icon="assets/logo.png", 
    layout="wide",
    initial_sidebar_state="expanded"
)

# Set Enterprise Logo in Sidebar
st.logo("assets/logo.png", icon_image="assets/logo.png")

# Custom CSS for Deep Enterprise Polish
st.markdown("""
<style>
    /* Hide Default Streamlit Elements */
    #MainMenu {visibility: hidden;}
    footer {visibility: hidden;}
    .stDeployButton {display:none;}
    
    /* Reduce top padding */
    .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
    }
    
    /* Metrics Styling - creating a sleek card effect */
    div[data-testid="metric-container"] {
        background-color: #12141c;
        border: 1px solid #1f2330;
        padding: 1.2rem;
        border-radius: 0.25rem;
        box-shadow: 0 4px 6px rgba(0, 0, 0, 0.4);
    }
    
    /* Hide the top decorative bar in st.metric */
    div[data-testid="stMetricDelta"] svg {
        display: none;
    }
    
    /* Typography improvements */
    h1, h2, h3, h4, h5 {
        font-family: 'Inter', sans-serif;
        font-weight: 500 !important;
        letter-spacing: -0.02em;
        color: #f8f9fa;
    }
    
    /* Adjust text colors slightly for better contrast on dark bg, but don't break buttons */
    .stMarkdown p, .stMarkdown span {
        font-family: 'Inter', sans-serif;
        color: #a0aec0;
    }
    
    /* Button Text Visibility Fix */
    .stButton button p {
        color: #ffffff !important;
        font-weight: 600 !important;
        letter-spacing: 0.5px;
    }
    
    /* Make the radio buttons in the sidebar look like modern navigation tabs */
    div[role="radiogroup"] > label > div:first-child {
        display: none;
    }
    div[role="radiogroup"] > label {
        padding: 0.5rem 1rem;
        margin-bottom: 0.25rem;
        border-radius: 0.25rem;
        background-color: transparent;
        transition: all 0.2s;
    }
    div[role="radiogroup"] > label:hover {
        background-color: #1a1e29;
    }
    div[role="radiogroup"] > label[data-checked="true"] {
        background-color: #1f2330;
        border-left: 3px solid #00d2ff;
    }
</style>
""", unsafe_allow_html=True)

# 2. Session State Management
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False
if 'scan_completed' not in st.session_state:
    st.session_state['scan_completed'] = False

# -----------------------------------------
# PAGE 1: SECURE LOGIN TERMINAL
# -----------------------------------------
if not st.session_state['authenticated']:
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br><br><br>", unsafe_allow_html=True)
        
        with st.container(border=True):
            col_logo1, col_logo2, col_logo3 = st.columns([1, 0.8, 1])
            with col_logo2:
                st.image("assets/logo.png", use_container_width=True)
            
            st.markdown("<h2 style='text-align: center; margin-bottom: 0; color: #fff;'>S.Q.A.N.</h2>", unsafe_allow_html=True)
            st.markdown("<p style='text-align: center; font-size: 0.8em; margin-top: 0; letter-spacing: 2px; color: #00d2ff;'>SCALABLE QUANTUM ARTEFACT NAVIGATOR</p>", unsafe_allow_html=True)
            st.divider()
            
            # Using st.form so pressing "Enter" triggers the login
            with st.form("login_form", clear_on_submit=False):
                username = st.text_input("OPERATOR ID", placeholder="admin")
                password = st.text_input("PASSCODE", type="password", placeholder="••••••••")
                
                st.markdown("<br>", unsafe_allow_html=True)
                submitted = st.form_submit_button("AUTHENTICATE SESSION", type="primary", use_container_width=True)
                
                if submitted:
                    if username == "admin" and password == "ntro2026":
                        st.session_state['authenticated'] = True
                        st.rerun()
                    else:
                        st.error("ACCESS DENIED: Invalid Credentials.")
            
            st.markdown("<p style='text-align: center; color: #444; font-size: 0.7rem; margin-top: 1.5rem; letter-spacing: 1px;'>RESTRICTED SYSTEM. ALL ATTEMPTS ARE LOGGED.</p>", unsafe_allow_html=True)

# -----------------------------------------
# PAGE 2: MAIN ENTERPRISE DASHBOARD
# -----------------------------------------
else:
    # --- SIDEBAR ---
    with st.sidebar:
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

    # --- MAIN CONTENT AREA ---
    
    if menu_selection == "OVERVIEW DASHBOARD":
        
        # TOP HEADER
        col_header1, col_header2 = st.columns([3, 1])
        with col_header1:
            st.header("Executive Quantum Risk Dashboard")
            st.markdown("Enterprise Cryptographic Discovery & Analysis Tool (ECDAT)")
        with col_header2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("EXPORT PDF REPORT", use_container_width=True):
                st.toast("PDF Report generation initiated.")
                
        st.divider()
        
        # TARGET SELECTION PANEL
        with st.container(border=True):
            st.markdown("##### Scan Configuration")
            col_cfg1, col_cfg2, col_cfg3 = st.columns([3, 1, 1])
            with col_cfg1:
                target_dir = st.text_input("TARGET PATH", value="C:/Projects/NTRO_Target/Core", label_visibility="collapsed")
            with col_cfg2:
                scan_mode = st.selectbox("ANALYSIS MODE", ["DEEP AST", "FAST REGEX", "BINARY ANALYSIS"], label_visibility="collapsed")
            with col_cfg3:
                run_scan = st.button("EXECUTE SCAN", type="primary", use_container_width=True)
                
        if run_scan:
            with st.spinner("Initializing parallel analysis engines... scanning codebase..."):
                time.sleep(2)
                st.session_state['scan_completed'] = True

        if st.session_state.get('scan_completed', False):
            # KPI METRICS
            st.markdown("<br>### Risk Telemetry", unsafe_allow_html=True)
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("TOTAL ARTEFACTS", "1,242", "Scan completed in 1.4s")
            m2.metric("CRITICAL RISK", "48", "-12 since last scan", delta_color="inverse")
            m3.metric("MEDIUM RISK", "156", "No change", delta_color="off")
            m4.metric("PQC COMPLIANT", "89", "+4 new compliant components", delta_color="normal")
            
            st.markdown("<br>", unsafe_allow_html=True)
            
            # CHARTS & ANALYSIS SECTION
            col_chart1, col_chart2 = st.columns([1, 1.2])
            
            with col_chart1:
                with st.container(border=True):
                    st.markdown("##### Cryptographic Algorithm Distribution")
                    labels = ['RSA', 'AES', 'ECDSA', 'SHA-2', 'ML-KEM (PQC)', 'Legacy Hash']
                    values = [350, 420, 180, 150, 89, 53]
                    
                    fig_donut = go.Figure(data=[go.Pie(
                        labels=labels, 
                        values=values, 
                        hole=.65,
                        marker=dict(colors=['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#06B6D4', '#64748B']),
                        textinfo='label+percent'
                    )])
                    fig_donut.update_layout(
                        margin=dict(t=10, b=10, l=10, r=10), 
                        height=220, 
                        showlegend=False,
                        paper_bgcolor='rgba(0,0,0,0)',
                        plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color="#a0aec0")
                    )
                    st.plotly_chart(fig_donut, use_container_width=True, config={'displayModeBar': False})
            
            with col_chart2:
                with st.container(border=True):
                    st.markdown("##### Mosca's Risk Simulator (X + Y > Z)")
                    
                    c1, c2, c3 = st.columns(3)
                    with c1: x_val = st.number_input("SHELF-LIFE (X)", 1, 30, 10)
                    with c2: y_val = st.number_input("MIGRATION (Y)", 1, 15, 3)
                    with c3: z_val = st.number_input("HORIZON (Z)", 1, 30, 7)
                    
                    total_time = x_val + y_val
                    danger_zone = total_time > z_val
                    
                    if danger_zone: 
                        st.error(f"CRITICAL EXPOSURE: X + Y ({total_time} yrs) > Z ({z_val} yrs)")
                    else: 
                        st.success(f"SECURE: X + Y ({total_time} yrs) ≤ Z ({z_val} yrs)")

            # RECENT DISCOVERIES TABLE
            st.markdown("<br>### Critical Discoveries", unsafe_allow_html=True)
            mock_data = {
                "FILE PATH": ["src/auth/jwt_handler.py", "core/payment_gateway.java", "crypto/cert_gen.c", "utils/hash_util.go", "config/tls_setup.yaml"],
                "ARTEFACT": ["RSA-2048", "AES-256-GCM", "ECDSA (P-256)", "MD5", "TLS 1.2"],
                "TYPE": ["Asymmetric Key", "Symmetric Cipher", "Digital Signature", "Hash Function", "Protocol"],
                "RISK LEVEL": ["High", "Safe", "High", "Critical", "Medium"],
                "REMEDIATION STRATEGY": ["Migrate to ML-KEM-768", "Maintain (Quantum-Resistant)", "Migrate to ML-DSA-65", "Deprecate immediately", "Upgrade to TLS 1.3"]
            }
            
            df = pd.DataFrame(mock_data)
            
            def color_risk(val):
                if val == 'Critical': return 'color: #EF4444; font-weight: 600'
                elif val == 'High': return 'color: #F87171; font-weight: 600'
                elif val == 'Medium': return 'color: #FBBF24; font-weight: 600'
                elif val == 'Safe': return 'color: #10B981; font-weight: 600'
                return ''
            
            try:
                styled_df = df.style.map(color_risk, subset=['RISK LEVEL'])
            except AttributeError:
                styled_df = df.style.applymap(color_risk, subset=['RISK LEVEL'])
                
            st.dataframe(styled_df, use_container_width=True, hide_index=True)

    else:
        st.header(menu_selection)
        st.info(f"The {menu_selection} module is currently running in background mode or requires additional privileges.")

from scanner import scan_directory

# Inside your Streamlit button click event:
if run_scan:
    results = scan_directory(target_dir, x_val, y_val, z_val)
    if results:
        df = pd.DataFrame(results)
        st.dataframe(df, use_container_width=True)