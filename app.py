import streamlit as st
import requests
import pandas as pd
import os

st.set_page_config(layout="wide")

st.title("🛡️ AutoVAPT Platform")
st.caption("Automated Vulnerability Assessment & Penetration Testing Engine")

# This dynamically finds your backend on Render's cloud servers automatically!
BACKEND_URL = os.getenv("BACKEND_URL", "http://backend-api:80")

col1, col2 = st.columns([1, 2])

with col1:
    st.header("🚀 Trigger Scan")
    target = st.text_input("Enter Target URL or IP Address:", placeholder="example.com")
    
    if st.button("Launch Scan", type="primary"):
        if target:
            with st.spinner("Executing live network assessment..."):
                try:
                    # Updated to use our cloud routing variable
                    response = requests.get(f"{BACKEND_URL}/run-scan?target={target}")
                    result = response.json()
                    
                    if result.get("status") == "Scan Completed":
                        st.success("Scan Completed Successfully!")
                        st.json(result)
                    else:
                        st.error(f"Scan failed: {result.get('details', 'Unknown network error')}")
                except Exception as e:
                    st.error(f"Could not connect to scanning engine backend: {e}")
        else:
            st.warning("Please enter a valid target asset.")

with col2:
    st.header("📊 Security Findings Logs (PostgreSQL)")
    if st.button("Refresh Log Data"):
        pass 
        
    try:
        # Updated to use our cloud routing variable
        response = requests.get(f"{BACKEND_URL}/findings")
        data = response.json()
        if data and isinstance(data, list):
            df = pd.DataFrame(data)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("No security logs stored in database yet.")
    except Exception as e:
        st.error(f"Error fetching logs from database: {e}")