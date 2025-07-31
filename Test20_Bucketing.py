import streamlit as st
import pandas as pd
import json
from cryptography.fernet import Fernet
import base64

st.set_page_config(page_title="Encrypted Question Clusters", layout="wide")
st.title("🔐 Secure Clustered Questions Viewer")
st.caption("⛳️Designed by Amartya 👨🏻‍💻")


# ========== ENCRYPTION HELPERS ==========
def get_fernet(key_str: str):
    # Ensure the key is valid base64
    try:
        key = base64.urlsafe_b64decode(key_str)
        return Fernet(base64.urlsafe_b64encode(key))
    except Exception:
        return None

def decrypt_json_file(file_path, fernet):
    try:
        with open(file_path, "rb") as f:
            encrypted_data = f.read()
        decrypted = fernet.decrypt(encrypted_data)
        return json.loads(decrypted.decode("utf-8"))
    except Exception as e:
        st.error(f"❌ Decryption failed: {e}")
        return None

# ========== SIDEBAR ==========
st.sidebar.header("🔐 Enter Decryption Key")
key_input = st.sidebar.text_input("Enter encryption key (Base64-encoded, 32 bytes):", type="password")

model_choice = st.sidebar.selectbox("🔎 Choose a Model", [
    "Mode A BERTTopic-48 V.2",
    "Model B BERTTopic-641 V.1",
    "Model C K-Means-5 V.1",
    "Model D K-Means-100 V.2"
])

file_map = {
    "Mode A BERTTopic-48 V.2": "new100.json.enc",
    "Model B BERTTopic-641 V.1": "clustered_questions_summary_model_bert.json.enc",
    "Model B K-Means-5 V.1": "clustered_questions_summary_model_k5.json.enc",
    "Model C K-Means-100 V.2": "clustered_questions_summary_model_k50.json.enc",
}
question_num_map={
    "Mode A BERTTopic-48 V.2":127681,
    "Model B BERTTopic-641 V.1": 64967,
    "Model B K-Means-5 V.1": 128803,
    "Model C K-Means-100 V.2": 128803,
}
json_file = file_map[model_choice]
TOTAL_QUESTIONS=question_num_map[model_choice]
if key_input:
    fernet = get_fernet(key_input.encode())
    if fernet:
        
        cluster_data = decrypt_json_file(json_file, fernet)
        if cluster_data:
            cluster_df = pd.DataFrame(cluster_data)
            cluster_df = cluster_df.sort_values(by='num_questions', ascending=False)

            st.subheader("⁉️All Representative Questions")
            for idx, row in cluster_df.iterrows():
                coverage_pct = (row['num_questions'] / TOTAL_QUESTIONS) * 100
                with st.expander(f"{row['representative_question']} **📊** Covers: **{coverage_pct:.2f}%** of all questions"):
                    st.write(f"**Total Questions**: {row['num_questions']}")  

                    if st.button(f"🔗 View all {row['num_questions']} Questions", key=f"btn_{row['cluster_id']}"):
                        st.markdown("---")
                        st.subheader(f"📌 All Questions for Cluster id {row['cluster_id']}")
                        for q in row['all_questions']:
                            st.write(f"• {q}")
                        st.subheader("✅ End of Cluster")
        else:
            st.error("⚠️ Failed to load cluster data.")
    else:
        st.warning("⚠️ Invalid decryption key format (should be 32-byte base64).")
else:
    st.info("🔐 Please enter the decryption key in the sidebar.")
