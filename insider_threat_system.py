#!/usr/bin/env python3
"""
Insider Threat Prediction System - Single-file prototype
Author: ChatGPT (GPT-5 Thinking mini)
Purpose: Internship project prototype demonstrating:
 - Tkinter GUI with ttk, fonts, messagebox
 - Simulated AI-driven predictive analysis (rule-based + explainability)
 - Sentiment analysis pipeline (lexicon-based)
 - Automated response mechanisms with approval/dry-run
 - Dashboard visualizations (tk.Canvas) and tables (ttk.Treeview)
 - Gamified challenge (points, badges, leaderboards)
 - Uses random, time, datetime, timedelta, webbrowser
Run: python insider_threat_system.py
"""

import tkinter as tk
from tkinter import ttk, font, messagebox
import random
import time
from datetime import datetime, timedelta
import webbrowser
import csv
import os

# ---------------------------
# Configuration / Constants
# ---------------------------
APP_TITLE = "Insider Threat Prediction System - Prototype"
SIM_EVENT_INTERVAL = 5  # seconds between simulated incoming events
DEFAULT_THRESHOLD = 0.65

# Palette & UI constants
COLOR_BG = "#05070f"
COLOR_GRADIENT_TOP = "#0c1224"
COLOR_GRADIENT_BOTTOM = "#05070f"
COLOR_SURFACE = "#11182c"
COLOR_SURFACE_ALT = "#141d34"
COLOR_CARD = "#1a2440"
COLOR_CARD_ELEVATED = "#202f55"
COLOR_ACCENT = "#4ad4c6"
COLOR_ACCENT_ALT = "#8a6bff"
COLOR_TEXT = "#f0f4ff"
COLOR_MUTED = "#8993b8"
COLOR_DANGER = "#ff6b6b"
COLOR_SUCCESS = "#58e6a7"
COLOR_WARNING = "#f7ad4a"
COLOR_BORDER = "#1f2a44"
COLOR_GLOW = "#233866"

# Simple sentiment lexicon (very small for prototype)
SENTIMENT_LEXICON = {
    "bad": -1, "angry": -1, "hate": -1, "suspicious": -1, "concern": -0.5,
    "sorry": -0.3, "help": -0.2, "thanks": 0.5, "great": 0.7, "ok": 0.1,
    "urgent": -0.5, "immediately": -0.4, "stressed": -0.8, "happy": 0.8
}

# Some mock users and departments
MOCK_USERS = [
    {"user_id": "u001", "name": "Alice", "dept": "Engineering"},
    {"user_id": "u002", "name": "Bob", "dept": "Finance"},
    {"user_id": "u003", "name": "Charlie", "dept": "HR"},
    {"user_id": "u004", "name": "Diana", "dept": "Sales"},
    {"user_id": "u005", "name": "Eve", "dept": "Research"},
]

# ---------------------------
# In-memory stores
# ---------------------------
EVENT_STORE = []      # incoming simulated events
ALERTS = []           # generated alerts
CASES = []            # created cases (after triage)
AUDIT_LOG = []        # automated actions / decisions
USER_POINTS = {u["user_id"]: 0 for u in MOCK_USERS}  # gamification for analysts (simulated)
BADGES = {u["user_id"]: set() for u in MOCK_USERS}

# ---------------------------
# Utility functions
# ---------------------------
def _hex_to_rgb(h: str) -> tuple[int, int, int]:
    h = h.lstrip("#")
    return tuple(int(h[i:i+2], 16) for i in (0, 2, 4))


def _rgb_to_hex(rgb: tuple[int, int, int]) -> str:
    return "#{:02x}{:02x}{:02x}".format(*rgb)


def blend_hex(color_a: str, color_b: str, t: float) -> str:
    """Blend two hex colors."""
    t = max(0.0, min(1.0, t))
    ca = _hex_to_rgb(color_a)
    cb = _hex_to_rgb(color_b)
    blended = tuple(int(ca[i] + (cb[i] - ca[i]) * t) for i in range(3))
    return _rgb_to_hex(blended)


def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def sentiment_score(text: str) -> float:
    """
    Very small lexicon-based sentiment scoring.
    Returns score between -1 (very negative) and +1 (very positive).
    """
    words = [w.strip(".,!?;:").lower() for w in text.split()]
    if not words:
        return 0.0
    s = 0.0
    count = 0
    for w in words:
        if w in SENTIMENT_LEXICON:
            s += SENTIMENT_LEXICON[w]
            count += 1
    if count == 0:
        # fallback: small neutral noise
        return 0.0
    score = s / max(1, count)
    # clamp
    return max(-1.0, min(1.0, score))

def human_readable_score(score: float) -> str:
    return f"{score*100:.0f}%"

# ---------------------------
# Prediction model (lightweight)
# ---------------------------
def compute_risk(features: dict) -> tuple[float, dict]:
    """
    Compute a risk score from feature dict.
    Features expected:
      - off_hours_activity: float (0-1)
      - file_downloads_last_24h: int
      - sentiment: float (-1..1)
      - usb_activity: int (0/1)
      - unusual_processes: int
    Returns (score, contributions)
    Implementation: weighted linear ensemble + anomaly boosts.
    """
    # weights - tunable
    weights = {
        "off_hours_activity": 0.30,
        "file_downloads": 0.25,
        "sentiment": -0.20,  # more negative sentiment -> higher risk (sentiment negative)
        "usb_activity": 0.12,
        "unusual_processes": 0.13
    }

    # normalize file downloads to 0..1 using a simple soft cap
    downloads_norm = min(1.0, features.get("file_downloads_last_24h", 0) / 50.0)

    # transform sentiment so negative -> positive risk contribution
    sent = features.get("sentiment", 0.0)
    sent_risk = max(0.0, -sent)  # negative sentiment -> risk; positive sentiment reduces risk

    base = (
        weights["off_hours_activity"] * features.get("off_hours_activity", 0.0)
        + weights["file_downloads"] * downloads_norm
        + weights["sentiment"] * sent
        + weights["usb_activity"] * (1.0 if features.get("usb_activity", 0) else 0.0)
        + weights["unusual_processes"] * min(1.0, features.get("unusual_processes", 0) / 5.0)
    )

    # anomaly boost: sudden spike in downloads or multiple adverse signals
    boost = 0.0
    if features.get("file_downloads_last_24h", 0) > 30:
        boost += 0.12
    if features.get("off_hours_activity", 0.0) > 0.6 and sent_risk > 0.3:
        boost += 0.10
    if features.get("usb_activity", 0) and features.get("file_downloads_last_24h", 0) > 10:
        boost += 0.08

    score = base + boost
    # clamp to 0..1
    score = max(0.0, min(1.0, score))
    # contributions for explainability
    contributions = {
        "off_hours_activity": weights["off_hours_activity"] * features.get("off_hours_activity", 0.0),
        "file_downloads": weights["file_downloads"] * downloads_norm,
        "sentiment": weights["sentiment"] * sent,
        "usb_activity": weights["usb_activity"] * (1.0 if features.get("usb_activity", 0) else 0.0),
        "unusual_processes": weights["unusual_processes"] * min(1.0, features.get("unusual_processes", 0) / 5.0),
        "anomaly_boost": boost
    }
    return score, contributions

# ---------------------------
# Event / Simulation
# ---------------------------
def simulate_event():
    """
    Create a simulated event and return it.
    """
    u = random.choice(MOCK_USERS)
    # simulate features
    off_hours = random.choices([0.1, 0.3, 0.6, 0.8], weights=[40, 30, 20, 10])[0]
    downloads = random.choices([0, 2, 6, 12, 40], weights=[30, 25, 20, 15, 10])[0]
    usb = random.choices([0,1], weights=[80,20])[0]
    unusual = random.choices([0,1,2,3], weights=[50,30,15,5])[0]
    # random message text for sentiment
    texts = [
        "Everything is ok, thanks team",
        "I am stressed and need help immediately",
        "This is urgent - send the files",
        "Suspicious activity spotted, please check",
        "Happy to finish the task",
        "I hate the new policy",
        "Please share credentials"
    ]
    text = random.choice(texts)
    s = sentiment_score(text)
    ev = {
        "event_id": f"ev_{int(time.time()*1000)}_{random.randint(100,999)}",
        "user_id": u["user_id"],
        "user_name": u["name"],
        "dept": u["dept"],
        "timestamp": datetime.now(),
        "off_hours_activity": off_hours,
        "file_downloads_last_24h": downloads,
        "usb_activity": usb,
        "unusual_processes": unusual,
        "message": text,
        "sentiment": s
    }
    EVENT_STORE.append(ev)
    return ev

# ---------------------------
# Alert generation & handling
# ---------------------------
def process_event_to_alert(ev, threshold=DEFAULT_THRESHOLD):
    features = {
        "off_hours_activity": ev["off_hours_activity"],
        "file_downloads_last_24h": ev["file_downloads_last_24h"],
        "sentiment": ev["sentiment"],
        "usb_activity": ev["usb_activity"],
        "unusual_processes": ev["unusual_processes"]
    }
    score, contributions = compute_risk(features)
    alert = {
        "alert_id": f"al_{int(time.time()*1000)}_{random.randint(10,99)}",
        "event": ev,
        "score": score,
        "contributions": contributions,
        "status": "New",
        "created_at": datetime.now(),
        "assigned_to": None,
        "case_id": None
    }
    ALERTS.append(alert)
    # auto-case creation if very high and auto action enabled (handled in UI)
    return alert

# ---------------------------
# Automated actions
# ---------------------------
def take_automated_action(alert, action, actor="system"):
    """
    Simulate taking an automated action. Record in AUDIT_LOG.
    action: str
    """
    ts = now_ts()
    log = {
        "timestamp": ts,
        "alert_id": alert["alert_id"],
        "action": action,
        "actor": actor,
        "score": alert["score"],
        "details": f"Action executed: {action}"
    }
    AUDIT_LOG.append(log)
    # change status if action is remediation
    if action in ("isolate_endpoint", "lock_account"):
        alert["status"] = "Mitigated"
    return log

# ---------------------------
# CSV Export helpers
# ---------------------------
def export_cases_csv(filepath="cases_export.csv"):
    keys = ["case_id", "alert_id", "user_id", "user_name", "dept", "score", "status", "assigned_to", "created_at"]
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(keys)
        for c in CASES:
            writer.writerow([
                c.get("case_id"),
                c.get("alert_id"),
                c.get("user_id"),
                c.get("user_name"),
                c.get("dept"),
                f"{c.get('score',0):.3f}",
                c.get("status"),
                c.get("assigned_to"),
                c.get("created_at").strftime("%Y-%m-%d %H:%M:%S")
            ])
    return filepath

# ---------------------------
# GUI
# ---------------------------
class ITSApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("1280x780")
        self.minsize(1150, 700)
        self.configure(bg=COLOR_BG)

        self.background_canvas = tk.Canvas(self, highlightthickness=0, bd=0, bg=COLOR_BG)
        self.background_canvas.place(relx=0, rely=0, relwidth=1, relheight=1)
        # Ensure the canvas sits behind other widgets
        self.background_canvas.lower("all")
        self.bind("<Configure>", self.draw_background_gradient)

        # fonts
        self.title_font = font.Font(family="Segoe UI", size=20, weight="bold")
        self.header_font = font.Font(family="Segoe UI", size=13, weight="bold")
        self.body_font = font.Font(family="Segoe UI", size=10)
        self.caption_font = font.Font(family="Segoe UI", size=9)
        self.metric_font = font.Font(family="Segoe UI", size=26, weight="bold")
        self.nav_font = font.Font(family="Segoe UI", size=10, weight="bold")
        self.nav_buttons = []

        # KPI vars
        self.kpi_new_alerts_var = tk.StringVar(value="0")
        self.kpi_open_cases_var = tk.StringVar(value="0")
        self.kpi_avg_score_var = tk.StringVar(value="0%")
        self.last_refresh_var = tk.StringVar(value="Syncing...")
        self.msg_sentiment_label_var = tk.StringVar(value="Sentiment: N/A")
        self.msg_sentiment_category_var = tk.StringVar(value="Neutral")
        self.sentiment_score_var = tk.DoubleVar(value=0.0)
        self.inbox_positive_var = tk.StringVar(value="0 positive")
        self.inbox_negative_var = tk.StringVar(value="0 negative")
        self.inbox_neutral_var = tk.StringVar(value="0 neutral")
        self.leaderboard_top_user_var = tk.StringVar(value="Awaiting analyst data")
        self.leaderboard_points_var = tk.StringVar(value="0 pts awarded")
        self.leaderboard_badges_var = tk.StringVar(value="0 elite badges")
        self.case_open_var = tk.StringVar(value="0 open")
        self.case_closed_var = tk.StringVar(value="0 closed")
        self.case_mitigated_var = tk.StringVar(value="0 mitigated")
        self.pred_score_text_var = tk.StringVar(value="Score: N/A")
        self.auto_threshold_label_var = tk.StringVar(value=f"{DEFAULT_THRESHOLD:.2f}")

        # top controls
        self.auto_action_enabled = tk.BooleanVar(value=False)
        self.auto_threshold = tk.DoubleVar(value=DEFAULT_THRESHOLD)
        self.auto_threshold.trace_add("write", lambda *args: self.auto_threshold_label_var.set(f"{self.auto_threshold.get():.2f}"))

        self.setup_theme()

        self.main_container = ttk.Frame(self, style="MainContainer.TFrame", padding=12)
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=18, pady=16)

        self.main_frame = ttk.Frame(self.main_container, style="Main.TFrame", padding=16)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.build_topbar(self.main_frame)

        # Notebook
        self.notebook = ttk.Notebook(self.main_frame, style="Hidden.TNotebook")

        # Tabs
        self.dashboard_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)
        self.predict_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)
        self.inbox_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)
        self.actions_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)
        self.gamify_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)
        self.settings_tab = ttk.Frame(self.notebook, style="Main.TFrame", padding=20)

        self.tab_order = [
            (self.dashboard_tab, "Dashboard"),
            (self.predict_tab, "Predict"),
            (self.inbox_tab, "Inbox / Sentiment"),
            (self.actions_tab, "Automated Actions / Cases"),
            (self.gamify_tab, "Gamification"),
            (self.settings_tab, "Settings")
        ]

        for frame, title in self.tab_order:
            self.notebook.add(frame, text=title)

        self.build_navbar(self.main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        # Build each tab
        self.build_dashboard()
        self.build_predict_tab()
        self.build_inbox_tab()
        self.build_actions_tab()
        self.build_gamify_tab()
        self.build_settings_tab()

        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_change)

        # Start visual/logic loops
        self.after(50, self.draw_background_gradient)
        self.after(1000, self.simulation_loop)

    def setup_theme(self):
        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.tk_setPalette(background=COLOR_BG, foreground=COLOR_TEXT, activeBackground=COLOR_CARD, activeForeground=COLOR_TEXT)
        self.option_add("*TCombobox*Listbox.background", COLOR_SURFACE)
        self.option_add("*TCombobox*Listbox.foreground", COLOR_TEXT)
        self.option_add("*TCombobox*Listbox.font", self.body_font)

        # Base styles
        self.style.configure("MainContainer.TFrame", background="", borderwidth=0)
        self.style.configure("Main.TFrame", background=COLOR_BG)
        self.style.configure("TopBar.TFrame", background=COLOR_BG)
        self.style.configure("NavBar.TFrame", background=COLOR_BG)
        self.style.configure("NavBarInner.TFrame", background=COLOR_BG)
        self.style.configure("Card.TFrame", background=COLOR_CARD, relief="flat", borderwidth=0)
        self.style.configure("CardHover.TFrame", background=COLOR_CARD_ELEVATED)
        self.style.configure("CardHighlight.TFrame", background=COLOR_SURFACE_ALT)
        self.style.configure("Hero.TFrame", background=COLOR_SURFACE_ALT)
        self.style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT, font=self.body_font)

        self.style.configure("Title.TLabel", background=COLOR_BG, foreground=COLOR_TEXT, font=self.title_font)
        self.style.configure("Subtitle.TLabel", background=COLOR_BG, foreground=COLOR_MUTED, font=self.body_font)
        self.style.configure("HeroTitle.TLabel", background=COLOR_SURFACE_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 18, "bold"))
        self.style.configure("HeroSubtitle.TLabel", background=COLOR_SURFACE_ALT, foreground=COLOR_MUTED, font=("Segoe UI", 11))
        self.style.configure("CardTitle.TLabel", background=COLOR_CARD, foreground=COLOR_MUTED, font=self.body_font)
        self.style.configure("CardValue.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT, font=self.metric_font)
        self.style.configure("KPIValue.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT, font=self.metric_font)
        self.style.configure("Badge.TLabel", background=COLOR_ACCENT_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 9, "bold"), padding=(10, 4))
        self.style.configure("PillAccent.TLabel", background=COLOR_ACCENT_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 10, "bold"), padding=(14, 6))
        self.style.configure("PillMuted.TLabel", background=COLOR_SURFACE_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 9, "bold"), padding=(10, 4))
        self.style.configure("ChipAccent.TLabel", background=COLOR_ACCENT, foreground="#001316", font=("Segoe UI", 9, "bold"), padding=(10, 4))
        self.style.configure("ChipWarning.TLabel", background=COLOR_WARNING, foreground="#1a1002", font=("Segoe UI", 9, "bold"), padding=(10, 4))
        self.style.configure("ChipMuted.TLabel", background=COLOR_SURFACE_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 9, "bold"), padding=(10, 4))
        self.style.configure("ScoreBadge.TLabel", background=COLOR_ACCENT_ALT, foreground=COLOR_TEXT, font=("Segoe UI", 16, "bold"), padding=(14, 6))
        self.style.configure("InfoLabel.TLabel", background=COLOR_CARD, foreground=COLOR_MUTED, font=("Segoe UI", 9))
        self.style.configure("InfoValue.TLabel", background=COLOR_CARD, foreground=COLOR_TEXT, font=("Segoe UI", 18, "bold"))

        self.style.configure("Accent.TButton", background=COLOR_ACCENT, foreground="#041820", borderwidth=0, padding=(16, 8), font=("Segoe UI", 10, "bold"))
        self.style.configure("Ghost.TButton", background=COLOR_SURFACE, foreground=COLOR_TEXT, borderwidth=0, padding=(12, 6), font=("Segoe UI", 10))
        self.style.configure("AccentOutline.TButton", background=COLOR_BG, foreground=COLOR_ACCENT, borderwidth=1, padding=(14, 8))
        self.style.configure("Nav.TButton", background=COLOR_SURFACE, foreground=COLOR_MUTED, padding=(14, 8), font=self.nav_font)
        self.style.configure("NavActive.TButton", background=COLOR_ACCENT_ALT, foreground=COLOR_TEXT, padding=(16, 10), font=self.nav_font)
        self.style.configure("TButton", background=COLOR_SURFACE, foreground=COLOR_TEXT, borderwidth=0, padding=(12, 6), font=("Segoe UI", 10))
        self.style.map("Accent.TButton", background=[("pressed", "#3cb4a7"), ("active", "#5ce0d1")])
        self.style.map("Ghost.TButton", background=[("pressed", COLOR_CARD), ("active", COLOR_SURFACE)], foreground=[("disabled", COLOR_MUTED)])
        self.style.map("Nav.TButton", background=[("active", COLOR_CARD)], foreground=[("active", COLOR_TEXT)])
        self.style.map("NavActive.TButton", background=[("active", COLOR_ACCENT)], foreground=[("active", COLOR_TEXT)])
        self.style.configure("Settings.TCheckbutton", background=COLOR_CARD, foreground=COLOR_TEXT)
        self.style.map("Settings.TCheckbutton", foreground=[("disabled", COLOR_MUTED)])

        self.style.configure("Modern.TNotebook", background=COLOR_BG, borderwidth=0, tabmargins=4)
        self.style.configure("Modern.TNotebook.Tab", background=COLOR_SURFACE, padding=(20, 10), foreground=COLOR_MUTED, font=("Segoe UI", 10, "bold"))
        self.style.map("Modern.TNotebook.Tab",
                       background=[("selected", COLOR_CARD)],
                       foreground=[("selected", COLOR_TEXT)])

        # Hidden notebook style (content only)
        self.style.layout("Hidden.TNotebook", [("Notebook.client", {"sticky": "nswe"})])
        self.style.configure("Hidden.TNotebook", background=COLOR_BG, borderwidth=0, padding=0)
        self.style.layout("Hidden.TNotebook.Tab", [])

        self.style.configure("Modern.Treeview", background=COLOR_SURFACE, fieldbackground=COLOR_SURFACE, foreground=COLOR_TEXT,
                             rowheight=30, borderwidth=0, relief="flat", highlightthickness=0)
        self.style.configure("Modern.Treeview.Heading", background=COLOR_CARD_ELEVATED, foreground=COLOR_TEXT,
                             font=("Segoe UI", 10, "bold"))
        self.style.map("Modern.Treeview", background=[("selected", COLOR_ACCENT_ALT)], foreground=[("selected", COLOR_TEXT)])

        self.style.configure("Score.Horizontal.TProgressbar", troughcolor=COLOR_SURFACE, background=COLOR_ACCENT,
                             bordercolor=COLOR_SURFACE, lightcolor=COLOR_ACCENT, darkcolor=COLOR_ACCENT)
        self.style.configure("TSeparator", background=COLOR_BORDER)
        self.style.configure("TScale", background=COLOR_CARD)

    def build_topbar(self, parent):
        topbar = ttk.Frame(parent, style="TopBar.TFrame")
        topbar.pack(fill=tk.X)
        left = ttk.Frame(topbar, style="TopBar.TFrame")
        left.pack(side=tk.LEFT, fill=tk.X, expand=True)

        title = ttk.Label(left, text="Insider Threat Command Center", style="Title.TLabel")
        title.pack(anchor="w")
        subtitle = ttk.Label(left, textvariable=self.last_refresh_var, style="Subtitle.TLabel")
        subtitle.pack(anchor="w", pady=(2, 8))

        badge = ttk.Label(left, text="LIVE FEED", style="Badge.TLabel")
        badge.pack(anchor="w")

        right = ttk.Frame(topbar, style="TopBar.TFrame")
        right.pack(side=tk.RIGHT)
        ttk.Button(right, text="Simulate Event", style="Accent.TButton", command=self.manual_simulate_event).pack(side=tk.LEFT, padx=6)
        ttk.Button(right, text="Run Sentiment Scan", style="Ghost.TButton", command=self.run_sentiment_scan).pack(side=tk.LEFT, padx=6)

    def build_navbar(self, parent):
        nav_container = ttk.Frame(parent, style="NavBar.TFrame")
        nav_container.pack(fill=tk.X, pady=(6, 10))
        nav_inner = ttk.Frame(nav_container, style="NavBarInner.TFrame")
        nav_inner.pack(fill=tk.X, pady=(4, 0))
        ttl = ttk.Label(nav_container, text="Command Modules", style="Subtitle.TLabel")
        ttl.pack(anchor="w")
        buttons_frame = ttk.Frame(nav_container, style="NavBarInner.TFrame")
        buttons_frame.pack(fill=tk.X, pady=(6, 2))

        for idx, (_, title) in enumerate(self.tab_order):
            btn = ttk.Button(
                buttons_frame,
                text=title,
                style="Nav.TButton",
                command=lambda i=idx: self.select_nav_tab(i)
            )
            btn.pack(side=tk.LEFT, padx=(0 if idx == 0 else 6, 6))
            self.nav_buttons.append(btn)

        self.nav_indicator = ttk.Separator(nav_container, orient=tk.HORIZONTAL)
        self.nav_indicator.pack(fill=tk.X, pady=(8, 0))
        self.on_tab_change()

    def select_nav_tab(self, index: int):
        if 0 <= index < len(self.tab_order):
            frame = self.tab_order[index][0]
            self.notebook.select(frame)

    def on_tab_change(self, event=None):
        current = self.notebook.index(self.notebook.select())
        for idx, btn in enumerate(self.nav_buttons):
            if idx == current:
                btn.configure(style="NavActive.TButton")
            else:
                btn.configure(style="Nav.TButton")

    def style_text_widget(self, widget):
        widget.configure(bg=COLOR_SURFACE_ALT, fg=COLOR_TEXT, insertbackground=COLOR_ACCENT,
                         highlightthickness=1, highlightbackground=COLOR_CARD_ELEVATED,
                         relief=tk.FLAT, bd=0, highlightcolor=COLOR_ACCENT)
        try:
            widget.configure(disabledforeground=COLOR_TEXT)
        except tk.TclError:
            pass

    def create_kpi_card(self, parent, title, value_var, extra_widget=None):
        card = ttk.Frame(parent, style="Card.TFrame", padding=18)
        ttk.Label(card, text=title, style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(card, textvariable=value_var, style="CardValue.TLabel").pack(anchor="w", pady=(6, 0))
        if extra_widget:
            extra_widget(card)
        self.register_card_hover(card)
        return card

    def register_card_hover(self, widget, base_style="Card.TFrame", hover_style="CardHover.TFrame"):
        def on_enter(_):
            widget.configure(style=hover_style)

        def on_leave(_):
            widget.configure(style=base_style)

        widget.bind("<Enter>", on_enter)
        widget.bind("<Leave>", on_leave)

    def create_scrollable_tab(self, parent):
        canvas = tk.Canvas(parent, bg=COLOR_BG, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=canvas.yview)
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        frame = ttk.Frame(canvas, style="Main.TFrame")
        window_id = canvas.create_window((0, 0), window=frame, anchor="nw")

        def on_frame_config(_):
            canvas.configure(scrollregion=canvas.bbox("all"))

        frame.bind("<Configure>", on_frame_config)

        def on_canvas_config(event):
            canvas.itemconfigure(window_id, width=event.width)

        canvas.bind("<Configure>", on_canvas_config)

        def _on_mousewheel(event):
            delta = -1 * int(event.delta / 120)
            canvas.yview_scroll(delta, "units")

        def _bind_mousewheel(_):
            canvas.bind_all("<MouseWheel>", _on_mousewheel)

        def _unbind_mousewheel(_):
            canvas.unbind_all("<MouseWheel>")

        canvas.bind("<Enter>", _bind_mousewheel)
        canvas.bind("<Leave>", _unbind_mousewheel)

        return frame

    # ---------------------------
    # Dashboard Tab
    # ---------------------------
    def build_dashboard(self):
        frame = self.create_scrollable_tab(self.dashboard_tab)
        hero = ttk.Frame(frame, style="Hero.TFrame", padding=20)
        hero.pack(fill=tk.X)
        hero_row = ttk.Frame(hero, style="Hero.TFrame")
        hero_row.pack(fill=tk.X)
        left_stack = ttk.Frame(hero, style="Hero.TFrame")
        left_stack.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Label(left_stack, text="Operational Overview", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(left_stack, text="Live AI risk telemetry, analyst workflow, and sentiment pulse.", style="HeroSubtitle.TLabel").pack(anchor="w", pady=(4, 10))
        badge_bar = ttk.Frame(left_stack, style="Hero.TFrame")
        badge_bar.pack(anchor="w", pady=(0, 6))
        ttk.Label(badge_bar, text="LIVE DATA STREAM", style="PillAccent.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Label(badge_bar, textvariable=self.last_refresh_var, style="PillMuted.TLabel").pack(side=tk.LEFT)
        hero_buttons = ttk.Frame(hero, style="Hero.TFrame")
        hero_buttons.pack(side=tk.RIGHT)
        ttk.Button(hero_buttons, text="Refresh", style="Accent.TButton", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=4)
        ttk.Button(hero_buttons, text="Export Cases CSV", style="Ghost.TButton", command=self.export_cases).pack(side=tk.LEFT, padx=4)

        kpi_frame = ttk.Frame(frame, style="Main.TFrame")
        kpi_frame.pack(fill=tk.X, pady=(18, 6))
        for col in range(3):
            kpi_frame.columnconfigure(col, weight=1, uniform="kpi")

        card_a = self.create_kpi_card(kpi_frame, "New Alerts", self.kpi_new_alerts_var)
        card_a.grid(row=0, column=0, sticky="nsew", padx=6)

        card_b = self.create_kpi_card(kpi_frame, "Open Cases", self.kpi_open_cases_var)
        card_b.grid(row=0, column=1, sticky="nsew", padx=6)

        def avg_extra(card):
            ttk.Label(card, text="Risk Trend", style="CardTitle.TLabel").pack(anchor="w", pady=(10, 2))
            self.avg_score_progress = ttk.Progressbar(card, style="Score.Horizontal.TProgressbar", maximum=100, mode="determinate")
            self.avg_score_progress.pack(fill=tk.X)

        card_c = self.create_kpi_card(kpi_frame, "Avg Score", self.kpi_avg_score_var, extra_widget=avg_extra)
        card_c.grid(row=0, column=2, sticky="nsew", padx=6)

        content = ttk.Frame(frame, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

        left = ttk.Frame(content, style="Main.TFrame")
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))

        right = ttk.Frame(content, style="Main.TFrame", width=360)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        alerts_panel = ttk.Frame(left, style="Card.TFrame", padding=18)
        alerts_panel.pack(fill=tk.BOTH, expand=True)
        self.register_card_hover(alerts_panel)
        header = ttk.Frame(alerts_panel, style="Card.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text="Recent Alerts", style="CardTitle.TLabel", font=self.header_font).pack(side=tk.LEFT)
        ttk.Button(header, text="Simulate Event", style="Ghost.TButton", command=self.manual_simulate_event).pack(side=tk.RIGHT)

        columns = ("alert_id", "user", "dept", "score", "status", "created_at")
        tree_container = ttk.Frame(alerts_panel, style="Card.TFrame")
        tree_container.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.alerts_tree = ttk.Treeview(tree_container, columns=columns, show="headings", height=12, style="Modern.Treeview")
        for c in columns:
            heading = c.replace("_", " ").title()
            self.alerts_tree.heading(c, text=heading, anchor="w")
            width = 140 if c not in ("score", "status") else 100
            self.alerts_tree.column(c, width=width, anchor="w", stretch=True)
        vsb = ttk.Scrollbar(tree_container, orient=tk.VERTICAL, command=self.alerts_tree.yview)
        self.alerts_tree.configure(yscrollcommand=vsb.set)
        self.alerts_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.alerts_tree.bind("<Double-1>", self.on_alert_double_click)
        self.alerts_tree.tag_configure("critical", background="#2c1d2f")
        self.alerts_tree.tag_configure("high", background="#1f2b46")
        self.alerts_tree.tag_configure("muted", foreground=COLOR_MUTED)
        self.alerts_tree.tag_configure("row-alt", background=COLOR_SURFACE_ALT)

        chart_frame = ttk.Frame(right, style="Card.TFrame", padding=16)
        chart_frame.pack(fill=tk.BOTH, expand=True)
        self.register_card_hover(chart_frame)
        ttk.Label(chart_frame, text="Alerts by Department", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        self.canvas = tk.Canvas(chart_frame, width=320, height=240, bg=COLOR_SURFACE, highlightthickness=0, bd=0)
        self.canvas.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        audit_frame = ttk.Frame(right, style="Card.TFrame", padding=16)
        audit_frame.pack(fill=tk.BOTH, expand=True, pady=(12, 0))
        self.register_card_hover(audit_frame)
        ttk.Label(audit_frame, text="Recent Audit Log", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        self.audit_list = tk.Text(audit_frame, height=8, wrap=tk.NONE)
        self.style_text_widget(self.audit_list)
        self.audit_list.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.refresh_dashboard()

    def refresh_dashboard(self):
        # KPIs
        new_alerts = sum(1 for a in ALERTS if a["status"] == "New")
        open_cases = len(CASES)
        avg_score = (sum(a["score"] for a in ALERTS) / max(1, len(ALERTS)))
        self.kpi_new_alerts_var.set(str(new_alerts))
        self.kpi_open_cases_var.set(str(open_cases))
        self.kpi_avg_score_var.set(f"{avg_score*100:.0f}%")
        if hasattr(self, "avg_score_progress") and self.avg_score_progress:
            self.avg_score_progress["value"] = avg_score * 100
        self.last_refresh_var.set(f"Updated {now_ts()}")

        # Refresh tree
        for i in self.alerts_tree.get_children():
            self.alerts_tree.delete(i)
        sorted_alerts = sorted(ALERTS, key=lambda x: x["created_at"], reverse=True)
        for idx, a in enumerate(sorted_alerts[:50]):
            tags = []
            if idx % 2 == 1:
                tags.append("row-alt")
            if a["score"] >= 0.8:
                tags.append("critical")
            elif a["score"] >= 0.6:
                tags.append("high")
            elif a["status"] in ("Mitigated", "Closed"):
                tags.append("muted")
            self.alerts_tree.insert("", tk.END, values=(
                a["alert_id"],
                a["event"]["user_name"],
                a["event"]["dept"],
                f"{a['score']:.2f}",
                a["status"],
                a["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            ), tags=tuple(tags))

        # Draw simple bar chart: top departments by alerts
        dept_counts = {}
        for a in ALERTS:
            dept_counts[a["event"]["dept"]] = dept_counts.get(a["event"]["dept"], 0) + 1
        items = sorted(dept_counts.items(), key=lambda x: x[1], reverse=True)
        self.canvas.delete("all")
        if items:
            maxv = max(v for _, v in items)
            x0 = 20
            y = 20
            for dept, v in items:
                bar_len = int((v / maxv) * 260)
                color = COLOR_ACCENT if bar_len < 180 else COLOR_ACCENT_ALT
                self.canvas.create_rectangle(x0, y, x0+bar_len, y+24, fill=color, outline=color)
                self.canvas.create_text(x0+bar_len+40, y+12, text=f"{dept} ({v})", anchor="w", fill=COLOR_TEXT, font=self.body_font)
                y += 36

        # Audit log
        self.audit_list.delete("1.0", tk.END)
        for l in AUDIT_LOG[-10:]:
            self.audit_list.insert(tk.END, f"{l['timestamp']} | {l['action']} | {l['alert_id']} | {l['actor']}\n")

    def on_alert_double_click(self, event):
        sel = self.alerts_tree.selection()
        if not sel:
            return
        vals = self.alerts_tree.item(sel[0])["values"]
        alert_id = vals[0]
        alert = next((a for a in ALERTS if a["alert_id"] == alert_id), None)
        if alert:
            self.open_alert_detail(alert)

    def open_alert_detail(self, alert):
        # popup window with explainability and actions
        w = tk.Toplevel(self)
        w.title(f"Alert Detail - {alert['alert_id']}")
        w.configure(bg=COLOR_BG)
        container = ttk.Frame(w, style="Main.TFrame", padding=18)
        container.pack(fill=tk.BOTH, expand=True)
        ttk.Label(container, text=f"User: {alert['event']['user_name']} ({alert['event']['user_id']})", style="Title.TLabel").pack(anchor="w")
        ttk.Label(container, text=f"Dept: {alert['event']['dept']}  |  Created: {alert['created_at'].strftime('%Y-%m-%d %H:%M:%S')}", style="Subtitle.TLabel").pack(anchor="w", pady=(0,8))

        # Contribution list
        frame = ttk.Frame(container, style="Card.TFrame", padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Risk Score", font=self.header_font).pack(anchor="w")
        ttk.Label(frame, text=f"{alert['score']:.3f} ({human_readable_score(alert['score'])})").pack(anchor="w")
        ttk.Label(frame, text="Top contributing features:", font=self.header_font).pack(anchor="w", pady=(8,2))
        for k,v in alert["contributions"].items():
            ttk.Label(frame, text=f"{k}: {v:.3f}").pack(anchor="w")

        ttk.Label(frame, text="Message:", font=self.header_font).pack(anchor="w", pady=(8,2))
        msg = tk.Text(frame, height=4, wrap=tk.WORD)
        msg.insert(tk.END, alert["event"]["message"])
        msg.config(state=tk.DISABLED)
        self.style_text_widget(msg)
        msg.pack(fill=tk.X)

        # Actions
        actions = ttk.Frame(container, style="Main.TFrame", padding=8)
        actions.pack(fill=tk.X)
        ttk.Button(actions, text="Assign to Analyst", style="Ghost.TButton", command=lambda: self.assign_alert(alert, w)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Create Case", style="Accent.TButton", command=lambda: self.create_case_from_alert(alert, w)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Notify via Email", style="Ghost.TButton", command=lambda: self.open_mail(alert)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Auto-Isolate", style="Accent.TButton", command=lambda: self.autoremediate(alert, w)).pack(side=tk.LEFT, padx=4)

    def assign_alert(self, alert, parent_w):
        # simple assign to random analyst (using MOCK_USERS as analyst pool)
        analyst = random.choice(MOCK_USERS)
        alert["assigned_to"] = analyst["user_id"]
        alert["status"] = "Triaged"
        messagebox.showinfo("Assigned", f"Alert {alert['alert_id']} assigned to {analyst['name']}")
        AUDIT_LOG.append({"timestamp": now_ts(), "alert_id": alert["alert_id"], "action": "assigned", "actor": "gui"})
        self.refresh_dashboard()
        parent_w.lift()

    def create_case_from_alert(self, alert, parent_w):
        case = {
            "case_id": f"case_{int(time.time()*1000)}",
            "alert_id": alert["alert_id"],
            "user_id": alert["event"]["user_id"],
            "user_name": alert["event"]["user_name"],
            "dept": alert["event"]["dept"],
            "score": alert["score"],
            "status": "Open",
            "assigned_to": alert.get("assigned_to"),
            "created_at": datetime.now()
        }
        CASES.append(case)
        alert["case_id"] = case["case_id"]
        alert["status"] = "Under Investigation"
        messagebox.showinfo("Case Created", f"Case {case['case_id']} created from alert {alert['alert_id']}")
        AUDIT_LOG.append({"timestamp": now_ts(), "alert_id": alert["alert_id"], "action": "case_created", "actor": "gui"})
        self.refresh_dashboard()
        parent_w.lift()

    def open_mail(self, alert):
        # open default mail client with a templated mail (mailto)
        subject = f"Security Alert: {alert['alert_id']} - {alert['event']['user_name']}"
        body = f"Dear Security Team,%0A%0AWe detected a risk score of {alert['score']:.2f} for user {alert['event']['user_name']} ({alert['event']['user_id']}).%0APlease review the alert: {alert['alert_id']}%0A%0AThanks."
        url = f"mailto:security@example.com?subject={subject}&body={body}"
        webbrowser.open(url)

    def autoremediate(self, alert, parent_w=None):
        if not self.auto_action_enabled.get():
            messagebox.showwarning("Auto-Action Disabled", "Enable auto actions in Settings to perform automated remediation.")
            return
        # follow approval gate logic: only auto isolate if score > threshold and auto_action_enabled
        thr = self.auto_threshold.get()
        if alert["score"] >= thr:
            take_automated_action(alert, "isolate_endpoint", actor="auto-system")
            messagebox.showinfo("Auto-Remediation", f"Auto action taken for {alert['alert_id']} (isolate_endpoint)")
            self.refresh_dashboard()
        else:
            messagebox.showinfo("Auto-Remediation Skipped", f"Alert {alert['alert_id']} score below threshold ({alert['score']:.2f} < {thr:.2f})")

    def export_cases(self):
        fp = export_cases_csv()
        messagebox.showinfo("Exported", f"Cases exported to {fp}")

    # ---------------------------
    # Predict Tab
    # ---------------------------
    def build_predict_tab(self):
        frame = self.create_scrollable_tab(self.predict_tab)
        hero = ttk.Frame(frame, style="Hero.TFrame", padding=18)
        hero.pack(fill=tk.X)
        ttk.Label(hero, text="Predictive What-If Analysis", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Test scenarios with simulated telemetry to preview AI risk responses.", style="HeroSubtitle.TLabel").pack(anchor="w", pady=(4, 0))
        hero_actions = ttk.Frame(hero, style="Hero.TFrame")
        hero_actions.pack(anchor="e")
        ttk.Button(hero_actions, text="Simulate Event Now", style="Ghost.TButton", command=self.manual_simulate_event).pack(side=tk.LEFT, padx=4)
        ttk.Button(hero_actions, text="Refresh Dashboard", style="Accent.TButton", command=self.refresh_dashboard).pack(side=tk.LEFT, padx=4)

        content = ttk.Frame(frame, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=16)
        content.columnconfigure(0, weight=1, uniform="predict")
        content.columnconfigure(1, weight=1, uniform="predict")

        left = ttk.Frame(content, style="Card.TFrame", padding=20)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.register_card_hover(left)
        ttk.Label(left, text="Analyst Input Controls", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(left, text="Craft user behavior patterns and contextual notes.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 8))

        form = ttk.Frame(left, style="Card.TFrame")
        form.pack(fill=tk.X, pady=(4, 0))

        self.user_var = tk.StringVar()
        user_names = [f'{u["user_id"]} - {u["name"]}' for u in MOCK_USERS]
        ttk.Label(form, text="Select User", style="CardTitle.TLabel").pack(anchor="w", pady=(6, 2))
        self.user_combo = ttk.Combobox(form, values=user_names, state="readonly", textvariable=self.user_var)
        self.user_combo.current(0)
        self.user_combo.pack(fill=tk.X)

        ttk.Label(form, text="Off-hours activity (0.0 - 1.0)", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 2))
        self.off_hours_var = tk.DoubleVar(value=0.1)
        ttk.Scale(form, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.off_hours_var).pack(fill=tk.X)

        ttk.Label(form, text="File downloads last 24h", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 2))
        self.downloads_var = tk.IntVar(value=2)
        ttk.Spinbox(form, from_=0, to=200, textvariable=self.downloads_var).pack(fill=tk.X)

        ttk.Label(form, text="USB activity (0/1)", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 2))
        self.usb_var = tk.IntVar(value=0)
        ttk.Checkbutton(form, text="USB used recently", variable=self.usb_var).pack(anchor="w")

        ttk.Label(form, text="Unusual processes (count)", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 2))
        self.unusual_var = tk.IntVar(value=0)
        ttk.Spinbox(form, from_=0, to=20, textvariable=self.unusual_var).pack(fill=tk.X)

        ttk.Label(form, text="Message text (affects sentiment)", style="CardTitle.TLabel").pack(anchor="w", pady=(12, 2))
        self.msg_entry = tk.Text(form, height=5, wrap=tk.WORD)
        self.msg_entry.insert(tk.END, "Everything is ok")
        self.msg_entry.pack(fill=tk.X)
        self.style_text_widget(self.msg_entry)

        actions = ttk.Frame(left, style="Card.TFrame")
        actions.pack(fill=tk.X, pady=(14, 0))
        ttk.Button(actions, text="Compute Risk", style="Accent.TButton", command=self.compute_manual_risk).pack(fill=tk.X)

        right = ttk.Frame(content, style="Card.TFrame", padding=20)
        right.grid(row=0, column=1, sticky="nsew")
        self.register_card_hover(right)
        header = ttk.Frame(right, style="Card.TFrame")
        header.pack(fill=tk.X)
        ttk.Label(header, text="Prediction Output", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        self.pred_score_lbl = ttk.Label(header, textvariable=self.pred_score_text_var, style="ScoreBadge.TLabel")
        self.pred_score_lbl.pack(anchor="w", pady=(10, 4))

        gauge = ttk.Frame(right, style="Card.TFrame")
        gauge.pack(fill=tk.X, pady=(4, 8))
        ttk.Label(gauge, text="Risk Gauge", style="InfoLabel.TLabel").pack(anchor="w")
        self.pred_risk_progress = ttk.Progressbar(gauge, style="Score.Horizontal.TProgressbar", maximum=100, mode="determinate")
        self.pred_risk_progress.pack(fill=tk.X)

        self.pred_explain = tk.Text(right, height=14, wrap=tk.WORD)
        self.style_text_widget(self.pred_explain)
        self.pred_explain.pack(fill=tk.BOTH, expand=True, pady=(10, 0))

    def manual_simulate_event(self):
        ev = simulate_event()
        alert = process_event_to_alert(ev)
        messagebox.showinfo("Event Simulated", f"Simulated event for {ev['user_name']} created as alert {alert['alert_id']}")
        # Auto-handle if auto enabled
        if self.auto_action_enabled.get() and alert["score"] >= self.auto_threshold.get():
            take_automated_action(alert, "isolate_endpoint", actor="auto-sim")
        self.refresh_dashboard()

    def compute_manual_risk(self):
        user = self.user_var.get().split(" - ")[0]
        off = self.off_hours_var.get()
        downloads = self.downloads_var.get()
        usb = self.usb_var.get()
        unusual = self.unusual_var.get()
        text = self.msg_entry.get("1.0", tk.END).strip()
        sent = sentiment_score(text)
        features = {
            "off_hours_activity": off,
            "file_downloads_last_24h": downloads,
            "sentiment": sent,
            "usb_activity": usb,
            "unusual_processes": unusual
        }
        score, contributions = compute_risk(features)
        self.pred_score_text_var.set(f"Score: {score:.3f} ({human_readable_score(score)})")
        if hasattr(self, "pred_risk_progress"):
            self.pred_risk_progress["value"] = score * 100
        self.pred_explain.delete("1.0", tk.END)
        self.pred_explain.insert(tk.END, f"Features:\n")
        for k, v in features.items():
            self.pred_explain.insert(tk.END, f"  {k}: {v}\n")
        self.pred_explain.insert(tk.END, "\nContributions:\n")
        for k, v in contributions.items():
            self.pred_explain.insert(tk.END, f"  {k}: {v:.3f}\n")
        # If user wants, create an alert from this manual run
        if messagebox.askyesno("Create Alert?", "Do you want to create an alert from this prediction?"):
            ev = {
                "event_id": f"ev_manual_{int(time.time())}",
                "user_id": user,
                "user_name": user,
                "dept": "Manual",
                "timestamp": datetime.now(),
                "off_hours_activity": off,
                "file_downloads_last_24h": downloads,
                "usb_activity": usb,
                "unusual_processes": unusual,
                "message": text,
                "sentiment": sent
            }
            EVENT_STORE.append(ev)
            alert = {
                "alert_id": f"al_manual_{int(time.time())}",
                "event": ev,
                "score": score,
                "contributions": contributions,
                "status": "New",
                "created_at": datetime.now(),
                "assigned_to": None,
                "case_id": None
            }
            ALERTS.append(alert)
            messagebox.showinfo("Alert Created", f"Alert {alert['alert_id']} created.")
            self.refresh_dashboard()

    # ---------------------------
    # Inbox / Sentiment Tab
    # ---------------------------
    def build_inbox_tab(self):
        frame = self.create_scrollable_tab(self.inbox_tab)
        hero = ttk.Frame(frame, style="Hero.TFrame", padding=18)
        hero.pack(fill=tk.X)
        ttk.Label(hero, text="Inbox & Sentiment Analyzer", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Surface tone shifts and escalate risky communications instantly.", style="HeroSubtitle.TLabel").pack(anchor="w")
        chips = ttk.Frame(hero, style="Hero.TFrame")
        chips.pack(anchor="w", pady=(10, 0))
        ttk.Label(chips, textvariable=self.inbox_positive_var, style="ChipAccent.TLabel").pack(side=tk.LEFT, padx=(0, 6))
        ttk.Label(chips, textvariable=self.inbox_negative_var, style="ChipWarning.TLabel").pack(side=tk.LEFT, padx=6)
        ttk.Label(chips, textvariable=self.inbox_neutral_var, style="ChipMuted.TLabel").pack(side=tk.LEFT, padx=6)
        ttk.Button(hero, text="Run Sentiment Scan", style="Accent.TButton", command=self.run_sentiment_scan).pack(anchor="e", pady=(8, 0))

        content = ttk.Frame(frame, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=16)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)

        left = ttk.Frame(content, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.register_card_hover(left)
        ttk.Label(left, text="Recent Messages", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(left, text="Double-click to inspect sentiment trail.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 8))
        self.inbox_tree = ttk.Treeview(left, columns=("msg", "user", "sentiment", "ts"), show="headings", height=20, style="Modern.Treeview")
        for c in ("msg", "user", "sentiment", "ts"):
            self.inbox_tree.heading(c, text=c.title())
            width = 180 if c == "msg" else 120
            self.inbox_tree.column(c, width=width, anchor="w")
        inbox_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.inbox_tree.yview)
        self.inbox_tree.configure(yscrollcommand=inbox_scroll.set)
        self.inbox_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        inbox_scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(4, 0))
        self.inbox_tree.bind("<Double-1>", self.on_message_open)
        self.inbox_tree.tag_configure("pos", foreground=COLOR_SUCCESS)
        self.inbox_tree.tag_configure("neg", foreground=COLOR_DANGER)
        self.inbox_tree.tag_configure("neu", foreground=COLOR_MUTED)
        self.inbox_tree.tag_configure("row-alt", background=COLOR_SURFACE_ALT)

        right = ttk.Frame(content, style="Card.TFrame", padding=18)
        right.grid(row=0, column=1, sticky="nsew")
        self.register_card_hover(right)
        ttk.Label(right, text="Message Detail", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(right, textvariable=self.msg_sentiment_label_var, style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 4))
        gauge = ttk.Frame(right, style="Card.TFrame")
        gauge.pack(fill=tk.X, pady=(4, 8))
        ttk.Label(gauge, textvariable=self.msg_sentiment_category_var, style="CardTitle.TLabel").pack(anchor="w")
        self.sentiment_progress = ttk.Progressbar(gauge, style="Score.Horizontal.TProgressbar", maximum=100)
        self.sentiment_progress.pack(fill=tk.X, expand=True)

        self.msg_detail = tk.Text(right, height=10, wrap=tk.WORD)
        self.style_text_widget(self.msg_detail)
        self.msg_detail.pack(fill=tk.BOTH, expand=True, pady=(10, 8))

        actions = ttk.Frame(right, style="Card.TFrame")
        actions.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(actions, text="Flag & Create Alert", style="Accent.TButton", command=self.flag_message_create_alert).pack(fill=tk.X, pady=4)
        ttk.Button(actions, text="Open Docs", style="Ghost.TButton", command=lambda: webbrowser.open("https://example.com/policies")).pack(fill=tk.X, pady=4)

        self.run_sentiment_scan()

    def run_sentiment_scan(self):
        # Build inbox from recent events
        self.inbox_tree.delete(*self.inbox_tree.get_children())
        # show last 50 messages
        msgs = EVENT_STORE[-50:]
        counts = {"pos": 0, "neg": 0, "neu": 0}
        for idx, m in enumerate(reversed(msgs)):
            s = m["sentiment"]
            tag = "pos" if s > 0.2 else ("neg" if s < -0.2 else "neu")
            counts[tag] += 1
            tags = [tag]
            if idx % 2 == 1:
                tags.append("row-alt")
            display_text = (m["message"][:40] + "...") if len(m["message"])>40 else m["message"]
            self.inbox_tree.insert("", tk.END, values=(display_text, m["user_name"], f"{s:.2f}", m["timestamp"].strftime("%Y-%m-%d %H:%M:%S")), tags=tuple(tags))
        self.inbox_positive_var.set(f"{counts['pos']} positive")
        self.inbox_negative_var.set(f"{counts['neg']} negative")
        self.inbox_neutral_var.set(f"{counts['neu']} neutral")

    def on_message_open(self, event):
        sel = self.inbox_tree.selection()
        if not sel:
            return
        vals = self.inbox_tree.item(sel[0])["values"]
        ts = vals[3]
        # find the event by timestamp
        ev = next((e for e in EVENT_STORE if e["timestamp"].strftime("%Y-%m-%d %H:%M:%S")==ts), None)
        if ev:
            self.msg_detail.delete("1.0", tk.END)
            self.msg_detail.insert(tk.END, f"From: {ev['user_name']} ({ev['user_id']})\nDept: {ev['dept']}\nTime: {ev['timestamp']}\n\n")
            self.msg_detail.insert(tk.END, ev["message"])
            s = ev["sentiment"]
            self.msg_sentiment_label_var.set(f"Sentiment score: {s:.2f}")
            category = "Positive tone" if s > 0.2 else ("Negative tone" if s < -0.2 else "Neutral tone")
            self.msg_sentiment_category_var.set(category)
            if hasattr(self, "sentiment_progress"):
                self.sentiment_progress["value"] = (s + 1) * 50

    def flag_message_create_alert(self):
        txt = self.msg_detail.get("1.0", tk.END)
        if not txt.strip():
            messagebox.showwarning("No Message", "Open a message first by double-clicking an item in the inbox.")
            return
        # find anchor by searching message substring in EVENT_STORE
        excerpt = txt.strip().splitlines()[-1][:80]
        ev = next((e for e in EVENT_STORE if excerpt in e["message"]), None)
        if not ev:
            messagebox.showerror("Not Found", "Could not find event to create alert from.")
            return
        alert = process_event_to_alert(ev)
        messagebox.showinfo("Alert Created", f"Alert {alert['alert_id']} created from message.")
        self.refresh_dashboard()

    # ---------------------------
    # Automated Actions / Cases Tab
    # ---------------------------
    def build_actions_tab(self):
        frame = self.create_scrollable_tab(self.actions_tab)
        hero = ttk.Frame(frame, style="Hero.TFrame", padding=18)
        hero.pack(fill=tk.X)
        ttk.Label(hero, text="Automated Actions & Casebook", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Monitor case load and govern remediation automation safeguards.", style="HeroSubtitle.TLabel").pack(anchor="w")
        stats = ttk.Frame(hero, style="Hero.TFrame")
        stats.pack(fill=tk.X, pady=(12, 0))
        for idx, (label, var) in enumerate([
            ("Open Cases", self.case_open_var),
            ("Mitigated Alerts", self.case_mitigated_var),
            ("Closed Cases", self.case_closed_var),
        ]):
            card = ttk.Frame(stats, style="Card.TFrame", padding=14)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if idx == 0 else 10, 0))
            self.register_card_hover(card)
            ttk.Label(card, text=label, style="InfoLabel.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=var, style="InfoValue.TLabel").pack(anchor="w")

        content = ttk.Frame(frame, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=16)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=2)

        left = ttk.Frame(content, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.register_card_hover(left)
        cols = ("case_id", "alert_id", "user", "dept", "score", "status", "created_at")
        ttk.Label(left, text="Casebook", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(left, text="Double-click a case to review or close.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 6))
        self.cases_tree = ttk.Treeview(left, columns=cols, show="headings", height=18, style="Modern.Treeview")
        for c in cols:
            self.cases_tree.heading(c, text=c.replace("_", " ").title())
            width = 110 if c not in ("case_id", "created_at") else 140
            self.cases_tree.column(c, width=width, anchor="w")
        case_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.cases_tree.yview)
        self.cases_tree.configure(yscrollcommand=case_scroll.set)
        self.cases_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        case_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.cases_tree.bind("<Double-1>", self.on_case_open)
        self.cases_tree.tag_configure("row-alt", background=COLOR_SURFACE_ALT)
        self.cases_tree.tag_configure("closed", foreground=COLOR_MUTED)

        right = ttk.Frame(content, style="Card.TFrame", padding=18)
        right.grid(row=0, column=1, sticky="nsew")
        self.register_card_hover(right)
        ttk.Label(right, text="Auto Action Controls", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Checkbutton(right, text="Enable Auto-Remediation", variable=self.auto_action_enabled, style="Settings.TCheckbutton").pack(anchor="w", pady=(8, 2))
        threshold_frame = ttk.Frame(right, style="Card.TFrame")
        threshold_frame.pack(fill=tk.X, pady=(6, 6))
        ttk.Label(threshold_frame, text="Auto Threshold ≥", style="InfoLabel.TLabel").pack(anchor="w")
        ttk.Label(threshold_frame, textvariable=self.auto_threshold_label_var, style="InfoValue.TLabel").pack(anchor="w")
        ttk.Scale(right, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.auto_threshold,
                  command=lambda v: self.auto_threshold_label_var.set(f"{float(v):.2f}")).pack(fill=tk.X)
        ttk.Button(right, text="Run Auto Action Sweep", style="Accent.TButton", command=self.run_auto_sweep).pack(fill=tk.X, pady=(16, 10))
        ttk.Button(right, text="Refresh Cases", style="Ghost.TButton", command=self.refresh_actions).pack(fill=tk.X)

        ttk.Label(right, text="Audit Log (last 20)", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w", pady=(18, 6))
        self.actions_audit = tk.Text(right, height=12, wrap=tk.WORD)
        self.style_text_widget(self.actions_audit)
        self.actions_audit.pack(fill=tk.BOTH, expand=True)

        self.refresh_actions()

    def refresh_actions(self):
        # refresh cases
        for i in self.cases_tree.get_children():
            self.cases_tree.delete(i)
        for idx, c in enumerate(sorted(CASES, key=lambda x: x["created_at"], reverse=True)):
            tags = ["row-alt"] if idx % 2 == 1 else []
            if c["status"] == "Closed":
                tags.append("closed")
            self.cases_tree.insert("", tk.END, values=(
                c["case_id"],
                c["alert_id"],
                c["user_name"],
                c["dept"],
                f"{c['score']:.2f}",
                c["status"],
                c["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            ), tags=tuple(tags))
        open_cases = sum(1 for c in CASES if c["status"] in ("Open", "Under Investigation"))
        closed_cases = sum(1 for c in CASES if c["status"] == "Closed")
        mitigated_alerts = sum(1 for a in ALERTS if a["status"] == "Mitigated")
        self.case_open_var.set(f"{open_cases} open")
        self.case_closed_var.set(f"{closed_cases} closed")
        self.case_mitigated_var.set(f"{mitigated_alerts} mitigated")
        # audit
        self.actions_audit.delete("1.0", tk.END)
        for l in AUDIT_LOG[-20:]:
            self.actions_audit.insert(tk.END, f"{l['timestamp']} | {l['action']} | {l['alert_id']}\n")

    def run_auto_sweep(self):
        thr = self.auto_threshold.get()
        if not self.auto_action_enabled.get():
            messagebox.showwarning("Disabled", "Enable auto-remediation first.")
            return
        cnt = 0
        for a in list(ALERTS):
            if a["status"] in ("Mitigated", "Under Investigation"):
                continue
            if a["score"] >= thr:
                take_automated_action(a, "isolate_endpoint", actor="auto-sweep")
                cnt += 1
        messagebox.showinfo("Auto Sweep Complete", f"Actions taken on {cnt} alerts.")
        self.refresh_dashboard()
        self.refresh_actions()

    def on_case_open(self, event):
        sel = self.cases_tree.selection()
        if not sel:
            return
        vals = self.cases_tree.item(sel[0])["values"]
        case_id = vals[0]
        case = next((c for c in CASES if c["case_id"] == case_id), None)
        if not case:
            return
        win = tk.Toplevel(self)
        win.title(f"Case {case_id}")
        ttk.Label(win, text=f"Case: {case_id}", font=self.header_font).pack(anchor="w", padx=8, pady=4)
        ttk.Label(win, text=f"User: {case['user_name']} ({case['user_id']})").pack(anchor="w", padx=8)
        ttk.Label(win, text=f"Score: {case['score']:.3f}").pack(anchor="w", padx=8, pady=4)
        ttk.Button(win, text="Mark Closed", command=lambda: self.close_case(case, win)).pack(padx=8, pady=8)

    def close_case(self, case, win):
        case["status"] = "Closed"
        AUDIT_LOG.append({"timestamp": now_ts(), "alert_id": case["alert_id"], "action": "case_closed", "actor": "analyst"})
        messagebox.showinfo("Closed", f"Case {case['case_id']} closed.")
        win.destroy()
        self.refresh_actions()
        self.refresh_dashboard()

    # ---------------------------
    # Gamification Tab
    # ---------------------------
    def build_gamify_tab(self):
        f = self.create_scrollable_tab(self.gamify_tab)
        hero = ttk.Frame(f, style="Hero.TFrame", padding=18)
        hero.pack(fill=tk.X)
        ttk.Label(hero, text="Gamification & Challenges", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Drive analyst engagement with points, badges, and sandbox drills.", style="HeroSubtitle.TLabel").pack(anchor="w")
        stats = ttk.Frame(hero, style="Hero.TFrame")
        stats.pack(fill=tk.X, pady=(12, 0))
        for idx, (label, var) in enumerate([
            ("Top Analyst", self.leaderboard_top_user_var),
            ("Total Points", self.leaderboard_points_var),
            ("Badges Earned", self.leaderboard_badges_var),
        ]):
            card = ttk.Frame(stats, style="Card.TFrame", padding=14)
            card.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0 if idx == 0 else 10, 0))
            self.register_card_hover(card)
            ttk.Label(card, text=label, style="InfoLabel.TLabel").pack(anchor="w")
            ttk.Label(card, textvariable=var, style="InfoValue.TLabel").pack(anchor="w")
        ttk.Button(hero, text="Refresh Leaderboard", style="Accent.TButton", command=self.refresh_gamify).pack(anchor="e", pady=(10, 0))

        content = ttk.Frame(f, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=16)
        content.columnconfigure(0, weight=2)
        content.columnconfigure(1, weight=3)

        left = ttk.Frame(content, style="Card.TFrame", padding=16)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.register_card_hover(left)
        ttk.Label(left, text="Leaderboard", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(left, text="Track analyst performance across missions.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 6))
        self.lb_tree = ttk.Treeview(left, columns=("user", "points"), show="headings", height=14, style="Modern.Treeview")
        self.lb_tree.heading("user", text="User")
        self.lb_tree.heading("points", text="Points")
        self.lb_tree.column("points", width=120, anchor="center")
        lb_scroll = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.lb_tree.yview)
        self.lb_tree.configure(yscrollcommand=lb_scroll.set)
        self.lb_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        lb_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.lb_tree.tag_configure("row-alt", background=COLOR_SURFACE_ALT)

        right = ttk.Frame(content, style="Main.TFrame")
        right.grid(row=0, column=1, sticky="nsew")
        right.columnconfigure(0, weight=1)

        sandbox_card = ttk.Frame(right, style="Card.TFrame", padding=16)
        sandbox_card.grid(row=0, column=0, sticky="nsew")
        self.register_card_hover(sandbox_card)
        ttk.Label(sandbox_card, text="Sandbox Challenge", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(sandbox_card, text="Simulate five alerts and grade analyst instincts.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 6))
        ttk.Button(sandbox_card, text="Start Sandbox (5 alerts)", style="Accent.TButton", command=self.start_sandbox).pack(fill=tk.X, pady=(0, 10))
        self.sandbox_log = tk.Text(sandbox_card, height=14)
        self.style_text_widget(self.sandbox_log)
        self.sandbox_log.pack(fill=tk.BOTH, expand=True)

        badge_card = ttk.Frame(right, style="Card.TFrame", padding=16)
        badge_card.grid(row=1, column=0, sticky="nsew", pady=(12, 0))
        self.register_card_hover(badge_card)
        ttk.Label(badge_card, text="Badges & Achievements", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        self.badge_summary = tk.Text(badge_card, height=8, wrap=tk.WORD)
        self.style_text_widget(self.badge_summary)
        self.badge_summary.pack(fill=tk.BOTH, expand=True, pady=(8, 0))

        self.refresh_gamify()

    def refresh_gamify(self):
        # populate leaderboard from USER_POINTS
        for i in self.lb_tree.get_children():
            self.lb_tree.delete(i)
        sorted_users = sorted(USER_POINTS.items(), key=lambda x: x[1], reverse=True)
        for idx, (uid, pts) in enumerate(sorted_users):
            name = next((u["name"] for u in MOCK_USERS if u["user_id"]==uid), uid)
            tags = ("row-alt",) if idx % 2 == 1 else ()
            self.lb_tree.insert("", tk.END, values=(name, pts), tags=tags)
        total_points = sum(USER_POINTS.values())
        top_entry = sorted_users[0] if sorted_users else None
        if top_entry:
            top_name = next((u["name"] for u in MOCK_USERS if u["user_id"] == top_entry[0]), top_entry[0])
            self.leaderboard_top_user_var.set(f"{top_name} ({top_entry[1]} pts)")
        else:
            self.leaderboard_top_user_var.set("Awaiting analyst data")
        self.leaderboard_points_var.set(f"{total_points} pts awarded")
        badge_total = sum(len(b) for b in BADGES.values())
        self.leaderboard_badges_var.set(f"{badge_total} badges")

        self.badge_summary.delete("1.0", tk.END)
        if badge_total == 0:
            self.badge_summary.insert(tk.END, "No badges earned yet. Run the sandbox challenge to unlock the first badge.")
        else:
            for uid, badges in BADGES.items():
                if not badges:
                    continue
                name = next((u["name"] for u in MOCK_USERS if u["user_id"] == uid), uid)
                badge_list = ", ".join(sorted(badges))
                self.badge_summary.insert(tk.END, f"{name}: {badge_list}\n")

    def start_sandbox(self):
        self.sandbox_log.delete("1.0", tk.END)
        sandbox_alerts = []
        for i in range(5):
            ev = simulate_event()
            alert = process_event_to_alert(ev)
            sandbox_alerts.append(alert)
            self.sandbox_log.insert(tk.END, f"[{len(sandbox_alerts)}] Alert {alert['alert_id']} for {alert['event']['user_name']} score {alert['score']:.2f}\n")
        # Let user triage via simple input dialog loop (simulate analyst)
        correct = 0
        for a in sandbox_alerts:
            ans = messagebox.askyesno("Sandbox Triage", f"Alert {a['alert_id']} (score {a['score']:.2f})\nMark as true positive?")
            # simple ground truth heuristic: score>0.6 => true positive
            truth = a["score"] > 0.60
            if ans == truth:
                correct += 1
        points_awarded = correct * 10
        # award to random analyst
        analyst = random.choice(MOCK_USERS)
        USER_POINTS[analyst["user_id"]] += points_awarded
        # badges
        if correct == 5:
            BADGES[analyst["user_id"]].add("Sandbox Master")
        self.sandbox_log.insert(tk.END, f"\nResult: {correct}/5 correct. {points_awarded} points awarded to {analyst['name']}.\n")
        self.refresh_gamify()

    # ---------------------------
    # Settings Tab
    # ---------------------------
    def build_settings_tab(self):
        f = self.create_scrollable_tab(self.settings_tab)
        hero = ttk.Frame(f, style="Hero.TFrame", padding=18)
        hero.pack(fill=tk.X)
        ttk.Label(hero, text="Settings & Configuration", style="HeroTitle.TLabel").pack(anchor="w")
        ttk.Label(hero, text="Tune automation, exports, and analyst resources.", style="HeroSubtitle.TLabel").pack(anchor="w")

        content = ttk.Frame(f, style="Main.TFrame")
        content.pack(fill=tk.BOTH, expand=True, pady=16)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=1)

        auto_card = ttk.Frame(content, style="Card.TFrame", padding=20)
        auto_card.grid(row=0, column=0, sticky="nsew", padx=(0, 12))
        self.register_card_hover(auto_card)
        ttk.Label(auto_card, text="Auto Remediation", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(auto_card, text="Control when automated isolation kicks in.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Checkbutton(auto_card, text="Enable Auto Remediation", variable=self.auto_action_enabled, style="Settings.TCheckbutton").pack(anchor="w")
        ttk.Label(auto_card, text="Auto threshold (0-1)", style="CardTitle.TLabel").pack(anchor="w", pady=(10, 2))
        ttk.Label(auto_card, textvariable=self.auto_threshold_label_var, style="InfoValue.TLabel").pack(anchor="w")
        ttk.Scale(auto_card, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.auto_threshold,
                  command=lambda v: self.auto_threshold_label_var.set(f"{float(v):.2f}")).pack(fill=tk.X, pady=(4, 8))
        ttk.Button(auto_card, text="Run Auto Sweep Now", style="Accent.TButton", command=self.run_auto_sweep).pack(fill=tk.X, pady=(8, 0))

        resources_card = ttk.Frame(content, style="Card.TFrame", padding=20)
        resources_card.grid(row=0, column=1, sticky="nsew")
        self.register_card_hover(resources_card)
        ttk.Label(resources_card, text="Resources & Utilities", style="CardTitle.TLabel", font=self.header_font).pack(anchor="w")
        ttk.Label(resources_card, text="Quick access to policy docs and exports.", style="InfoLabel.TLabel").pack(anchor="w", pady=(0, 10))
        ttk.Button(resources_card, text="Export Cases CSV", style="Ghost.TButton", command=self.export_cases).pack(fill=tk.X, pady=4)
        ttk.Button(resources_card, text="Open Policy Docs", style="Accent.TButton",
                   command=lambda: webbrowser.open("https://example.com/policies")).pack(fill=tk.X, pady=4)
        ttk.Button(resources_card, text="Simulate Event", style="Ghost.TButton", command=self.manual_simulate_event).pack(fill=tk.X, pady=4)
        ttk.Label(resources_card, text="Need more controls? Extend this panel with API keys, alert routing, and directory sync options.", style="InfoLabel.TLabel").pack(anchor="w", pady=(12, 0))

    def draw_background_gradient(self, event=None):
        if not hasattr(self, "background_canvas"):
            return
        width = max(1, self.winfo_width())
        height = max(1, self.winfo_height())
        self.background_canvas.delete("gradient")
        steps = 80
        for i in range(steps):
            ratio = i / steps
            color = blend_hex(COLOR_GRADIENT_TOP, COLOR_GRADIENT_BOTTOM, ratio)
            y0 = int(i * height / steps)
            y1 = int((i + 1) * height / steps)
            self.background_canvas.create_rectangle(0, y0, width, y1, fill=color, outline="", tags="gradient")
        self.background_canvas.create_oval(
            width * 0.6,
            -height * 0.3,
            width * 1.1,
            height * 0.2,
            fill=blend_hex(COLOR_GLOW, COLOR_BG, 0.4),
            outline="",
            tags="gradient"
        )
        self.background_canvas.create_oval(
            -width * 0.2,
            height * 0.55,
            width * 0.35,
            height * 1.1,
            fill=blend_hex(COLOR_ACCENT_ALT, COLOR_BG, 0.7),
            outline="",
            tags="gradient"
        )
        self.background_canvas.lower("all")

    # ---------------------------
    # Simulation Loop
    # ---------------------------
    def simulation_loop(self):
        # Simulate an event
        ev = simulate_event()
        alert = process_event_to_alert(ev)
        # If auto action enabled and score above threshold, take action
        if self.auto_action_enabled.get() and alert["score"] >= self.auto_threshold.get():
            take_automated_action(alert, "isolate_endpoint", actor="auto-sim")
        # keep UI updated
        self.refresh_dashboard()
        # schedule next
        self.after(SIM_EVENT_INTERVAL * 1000, self.simulation_loop)


# ---------------------------
# Run the app
# ---------------------------
def main():
    # prepare a few simulated historical events
    for _ in range(8):
        ev = simulate_event()
        process_event_to_alert(ev)
    app = ITSApp()
    app.mainloop()

if __name__ == "__main__":
    main()
