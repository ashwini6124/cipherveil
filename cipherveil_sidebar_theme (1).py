"""
CipherVeil — Sidebar theme
--------------------------
Paste this into your app (e.g. a file called theme.py) and call
inject_sidebar_theme() ONCE, right after st.set_page_config(...).

    from theme import inject_sidebar_theme
    inject_sidebar_theme()

Colour palette (matches the dark main panel):
    --cv-bg-deep   #060d1a   deepest navy
    --cv-bg        #0a1628   sidebar background
    --cv-panel     #101c30   raised cards / inputs
    --cv-border    #1e3a5f   subtle borders
    --cv-accent    #22d3ee   cyan accent (headings, glow)
    --cv-accent-2  #4ade80   green accent (status/log text)
    --cv-text      #e6f1ff   primary text
    --cv-muted     #8ea3c4   secondary text
"""

import streamlit as st

SIDEBAR_CSS = """
<style>
:root {
    --cv-bg-deep:  #060d1a;
    --cv-bg:       #0a1628;
    --cv-panel:    #101c30;
    --cv-border:   #1e3a5f;
    --cv-accent:   #22d3ee;
    --cv-accent-2: #4ade80;
    --cv-text:     #e6f1ff;
    --cv-muted:    #8ea3c4;
}

/* ---------- Sidebar container ---------- */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, var(--cv-bg) 0%, var(--cv-bg-deep) 100%);
    border-right: 1px solid var(--cv-border);
    box-shadow: 2px 0 20px rgba(0, 0, 0, 0.45);
}

section[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.2rem;
}

/* ---------- All text inside the sidebar ---------- */
section[data-testid="stSidebar"] * {
    color: var(--cv-text);
}

section[data-testid="stSidebar"] p,
section[data-testid="stSidebar"] li,
section[data-testid="stSidebar"] label,
section[data-testid="stSidebar"] span {
    color: var(--cv-text);
    font-size: 14.5px;
}

/* Headings get the cyan accent + soft glow */
section[data-testid="stSidebar"] h1,
section[data-testid="stSidebar"] h2,
section[data-testid="stSidebar"] h3,
section[data-testid="stSidebar"] h4 {
    color: var(--cv-accent);
    letter-spacing: 0.4px;
    text-shadow: 0 0 10px rgba(34, 211, 238, 0.25);
}

/* Muted captions (st.caption / small helper text) */
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"],
section[data-testid="stSidebar"] [data-testid="stCaptionContainer"] * {
    color: var(--cv-muted);
}

/* ---------- Bullet lists (team members) ---------- */
section[data-testid="stSidebar"] ul {
    padding-left: 1.1rem;
}
section[data-testid="stSidebar"] li {
    margin-bottom: 6px;
}
section[data-testid="stSidebar"] li::marker {
    color: var(--cv-accent);
}

/* ---------- Divider ---------- */
section[data-testid="stSidebar"] hr {
    border: none;
    height: 1px;
    background: linear-gradient(90deg,
        transparent, var(--cv-border) 20%, var(--cv-border) 80%, transparent);
    margin: 1.3rem 0;
}

/* ---------- Text / number / password inputs ---------- */
section[data-testid="stSidebar"] input,
section[data-testid="stSidebar"] textarea {
    background-color: var(--cv-panel) !important;
    color: var(--cv-text) !important;
    border: 1px solid var(--cv-border) !important;
    border-radius: 8px !important;
}
section[data-testid="stSidebar"] input:focus,
section[data-testid="stSidebar"] textarea:focus {
    border-color: var(--cv-accent) !important;
    box-shadow: 0 0 0 2px rgba(34, 211, 238, 0.18) !important;
}
section[data-testid="stSidebar"] input::placeholder {
    color: var(--cv-muted) !important;
}

/* ---------- Selectbox / multiselect ---------- */
section[data-testid="stSidebar"] div[data-baseweb="select"] > div {
    background-color: var(--cv-panel) !important;
    border: 1px solid var(--cv-border) !important;
    border-radius: 8px !important;
    color: var(--cv-text) !important;
}

/* ---------- Buttons ---------- */
section[data-testid="stSidebar"] button[kind],
section[data-testid="stSidebar"] .stButton > button,
section[data-testid="stSidebar"] .stDownloadButton > button {
    background: linear-gradient(135deg, #12263f, #0d1b2e);
    color: var(--cv-text);
    border: 1px solid var(--cv-border);
    border-radius: 9px;
    font-weight: 600;
    letter-spacing: 0.3px;
    transition: all 0.18s ease-in-out;
    width: 100%;
}
section[data-testid="stSidebar"] .stButton > button:hover,
section[data-testid="stSidebar"] .stDownloadButton > button:hover {
    border-color: var(--cv-accent);
    color: var(--cv-accent);
    box-shadow: 0 0 14px rgba(34, 211, 238, 0.28);
    transform: translateY(-1px);
}

/* ---------- File uploader ---------- */
section[data-testid="stSidebar"] [data-testid="stFileUploaderDropzone"] {
    background-color: var(--cv-panel);
    border: 1px dashed var(--cv-border);
    border-radius: 10px;
}

/* ---------- Radio / checkbox ---------- */
section[data-testid="stSidebar"] [data-testid="stRadio"] label,
section[data-testid="stSidebar"] [data-testid="stCheckbox"] label {
    color: var(--cv-text);
}

/* ---------- Expander ---------- */
section[data-testid="stSidebar"] [data-testid="stExpander"] {
    background-color: var(--cv-panel);
    border: 1px solid var(--cv-border);
    border-radius: 10px;
}

/* ---------- Collapse arrow ---------- */
section[data-testid="stSidebar"] [data-testid="stSidebarCollapseButton"] svg {
    fill: var(--cv-muted);
}

/* ---------- Scrollbar ---------- */
section[data-testid="stSidebar"] ::-webkit-scrollbar {
    width: 7px;
}
section[data-testid="stSidebar"] ::-webkit-scrollbar-track {
    background: transparent;
}
section[data-testid="stSidebar"] ::-webkit-scrollbar-thumb {
    background: var(--cv-border);
    border-radius: 4px;
}
section[data-testid="stSidebar"] ::-webkit-scrollbar-thumb:hover {
    background: var(--cv-accent);
}

/* ---------- Chatbot card ---------- */
.cv-chatbot-card {
    background: linear-gradient(145deg, #0f1c30, #13223a);
    border: 1px solid rgba(34, 211, 238, 0.28);
    border-radius: 14px;
    padding: 14px 16px;
    margin-top: 8px;
    box-shadow: 0 0 18px rgba(34, 211, 238, 0.10);
}
.cv-chatbot-header {
    display: flex;
    align-items: center;
    gap: 10px;
}
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
.cv-chatbot-name {
    font-weight: 700;
    font-size: 16px;
    color: #e6f1ff;
    letter-spacing: 0.3px;
}
.cv-chatbot-subtitle {
    font-size: 12.5px;
    color: var(--cv-muted);
    margin-left: 44px;
    margin-top: 2px;
}

/* ---------- Secure-session badge ---------- */
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
    """Call once per page, immediately after st.set_page_config()."""
    st.markdown(SIDEBAR_CSS, unsafe_allow_html=True)
