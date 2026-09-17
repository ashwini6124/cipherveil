import streamlit as st

SIDEBAR_CSS = """
<style>
:root {
    --cv-bg-deep: #060d1a;
    --cv-bg: #0a1628;
    --cv-panel: #101c30;
    --cv-border: #1e3a5f;
    --cv-accent: #22d3ee;
    --cv-accent-2: #4ade80;
    --cv-text: #e6f1ff;
    --cv-muted: #8ea3c4;
}
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, var(--cv-bg) 0%, var(--cv-bg-deep) 100%);
    border-right: 1px solid var(--cv-border);
    box-shadow: 2px 0 20px rgba(0, 0, 0, 0.45);
}
section[data-testid="stSidebar"] * { color: var(--cv-text); }
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] h4 {
    color: var(--cv-accent);
    text-shadow: 0 0 10px rgba(34, 211, 238, 0.25);
}
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"],
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * { color: var(--cv-muted); }
section[data-testid="stSidebar"] li::marker { color: var(--cv-accent); }
section[data-testid="stSidebar"] hr {
    border: none;
    height: 1px;
    background: linear-gradient(90deg, transparent, var(--cv-border) 20%, var(--cv-border) 80%, transparent);
}
section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] textarea {
    background-color: var(--cv-panel) !important;
    color: var(--cv-text) !important;
    border: 1px solid var(--cv-border) !important;
    border-radius: 8px !important;
}
section[data-testid="stSidebar"] button[kind],
section[data-testid="stSidebar"] .stButton > button {
    background: linear-gradient(135deg, #12263f, #0d1b2e);
    color: var(--cv-text);
    border: 1px solid var(--cv-border);
    border-radius: 9px;
}
section[data-testid="stSidebar"] .stButton > button:hover {
    border-color: var(--cv-accent);
    color: var(--cv-accent);
    box-shadow: 0 0 14px rgba(34, 211, 238, 0.28);
}
.cv-chatbot-card {
    background: linear-gradient(145deg, #0f1c30, #13223a);
    border: 1px solid rgba(34, 211, 238, 0.28);
    border-radius: 14px;
    padding: 14px 16px;
    margin-top: 8px;
    box-shadow: 0 0 18px rgba(34, 211, 238, 0.10);
}
.cv-chatbot-header { display: flex; align-items: center; gap: 10px; }
.cv-chatbot-badge {
    width: 34px;
    height: 34px;
    border-radius: 50%;
    background: radial-gradient(circle at 30% 30%, #67e8f9, #0e7490);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 18px;
    box-shadow: 0 0 12px rgba(34, 211, 238, 0.45);
}
.cv-chatbot-name { font-weight: 700; font-size: 16px; color: #e6f1ff; }
.cv-chatbot-subtitle { font-size: 12.5px; color: var(--cv-muted); margin-left: 44px; margin-top: 2px; }
.cv-session-badge {
    display: inline-flex;
    align-items: center;
    gap: 7px;
    background: rgba(74, 222, 128, 0.10);
    border: 1px solid rgba(74, 222, 128, 0.35);
    color: var(--cv-accent-2);
    border-radius: 999px;
    padding: 4px 12px;
    font-size: 12.5px;
    font-weight: 600;
}
</style>
"""

CHATBOT_CARD_HTML = """
<div class="cv-chatbot-card">
    <div class="cv-chatbot-header">
        <div class="cv-chatbot-badge">🤖</div>
        <div class="cv-chatbot-name">VeilBot</div>
    </div>
    <div class="cv-chatbot-subtitle">Gemini-powered help on every page</div>
</div>
"""

SESSION_BADGE_HTML = '<div class="cv-session-badge">🔒 Secure Session</div>'


def inject_sidebar_theme():
    st.markdown(SIDEBAR_CSS, unsafe_allow_html=True)
