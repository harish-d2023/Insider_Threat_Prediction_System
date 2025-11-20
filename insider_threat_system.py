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
        self.geometry("1100x700")
        # fonts
        self.title_font = font.Font(family="Helvetica", size=14, weight="bold")
        self.header_font = font.Font(family="Helvetica", size=11, weight="bold")
        # top controls
        self.auto_action_enabled = tk.BooleanVar(value=False)
        self.auto_threshold = tk.DoubleVar(value=DEFAULT_THRESHOLD)

        # Notebook
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.predict_tab = ttk.Frame(self.notebook)
        self.inbox_tab = ttk.Frame(self.notebook)
        self.actions_tab = ttk.Frame(self.notebook)
        self.gamify_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)

        for tab, title in [
            (self.dashboard_tab, "Dashboard"),
            (self.predict_tab, "Predict"),
            (self.inbox_tab, "Inbox / Sentiment"),
            (self.actions_tab, "Automated Actions / Cases"),
            (self.gamify_tab, "Gamification"),
            (self.settings_tab, "Settings")
        ]:
            self.notebook.add(tab, text=title)

        # Build each tab
        self.build_dashboard()
        self.build_predict_tab()
        self.build_inbox_tab()
        self.build_actions_tab()
        self.build_gamify_tab()
        self.build_settings_tab()

        # Start simulation loop
        self.after(1000, self.simulation_loop)

    # ---------------------------
    # Dashboard Tab
    # ---------------------------
    def build_dashboard(self):
        frame = self.dashboard_tab
        top_frame = ttk.Frame(frame, padding=8)
        top_frame.pack(fill=tk.X)
        ttk.Label(top_frame, text="Dashboard", font=self.title_font).pack(side=tk.LEFT)
        refresh_btn = ttk.Button(top_frame, text="Refresh", command=self.refresh_dashboard)
        refresh_btn.pack(side=tk.RIGHT)
        export_btn = ttk.Button(top_frame, text="Export Cases CSV", command=self.export_cases)
        export_btn.pack(side=tk.RIGHT, padx=6)

        content = ttk.Frame(frame, padding=10)
        content.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(content)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right = ttk.Frame(content, width=350)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        # KPI cards (simple labels)
        kpi_frame = ttk.Frame(left)
        kpi_frame.pack(fill=tk.X)
        self.kpi_new_alerts = ttk.Label(kpi_frame, text="New Alerts: 0", font=self.header_font)
        self.kpi_new_alerts.pack(side=tk.LEFT, padx=8)
        self.kpi_open_cases = ttk.Label(kpi_frame, text="Open Cases: 0", font=self.header_font)
        self.kpi_open_cases.pack(side=tk.LEFT, padx=8)
        self.kpi_avg_score = ttk.Label(kpi_frame, text="Avg Score: 0%", font=self.header_font)
        self.kpi_avg_score.pack(side=tk.LEFT, padx=8)

        # Alerts table
        tb_frame = ttk.LabelFrame(left, text="Recent Alerts")
        tb_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        columns = ("alert_id", "user", "dept", "score", "status", "created_at")
        self.alerts_tree = ttk.Treeview(tb_frame, columns=columns, show="headings", height=12)
        for c in columns:
            self.alerts_tree.heading(c, text=c.replace("_", " ").title())
            self.alerts_tree.column(c, width=120)
        self.alerts_tree.pack(fill=tk.BOTH, expand=True)
        self.alerts_tree.bind("<Double-1>", self.on_alert_double_click)

        # Right: simple charts via canvas
        chart_frame = ttk.LabelFrame(right, text="Visuals")
        chart_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.canvas = tk.Canvas(chart_frame, width=320, height=300, bg="white")
        self.canvas.pack(padx=6, pady=6)

        # Audit log small list
        audit_frame = ttk.LabelFrame(right, text="Recent Audit Log")
        audit_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.audit_list = tk.Text(audit_frame, height=8, wrap=tk.NONE)
        self.audit_list.pack(fill=tk.BOTH, expand=True)

        self.refresh_dashboard()

    def refresh_dashboard(self):
        # KPIs
        new_alerts = sum(1 for a in ALERTS if a["status"] == "New")
        open_cases = len(CASES)
        avg_score = (sum(a["score"] for a in ALERTS) / max(1, len(ALERTS)))
        self.kpi_new_alerts.config(text=f"New Alerts: {new_alerts}")
        self.kpi_open_cases.config(text=f"Open Cases: {open_cases}")
        self.kpi_avg_score.config(text=f"Avg Score: {avg_score*100:.0f}%")

        # Refresh tree
        for i in self.alerts_tree.get_children():
            self.alerts_tree.delete(i)
        sorted_alerts = sorted(ALERTS, key=lambda x: x["created_at"], reverse=True)
        for a in sorted_alerts[:50]:
            self.alerts_tree.insert("", tk.END, values=(
                a["alert_id"],
                a["event"]["user_name"],
                a["event"]["dept"],
                f"{a['score']:.2f}",
                a["status"],
                a["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            ))

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
                self.canvas.create_rectangle(x0, y, x0+bar_len, y+24, fill="#4f8ef7")
                self.canvas.create_text(x0+bar_len+40, y+12, text=f"{dept} ({v})", anchor="w")
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
        ttk.Label(w, text=f"User: {alert['event']['user_name']} ({alert['event']['user_id']})", font=self.header_font).pack(anchor="w", padx=8, pady=4)
        ttk.Label(w, text=f"Dept: {alert['event']['dept']}  |  Created: {alert['created_at'].strftime('%Y-%m-%d %H:%M:%S')}").pack(anchor="w", padx=8)

        # Contribution list
        frame = ttk.Frame(w, padding=8)
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
        msg.pack(fill=tk.X)

        # Actions
        actions = ttk.Frame(w, padding=8)
        actions.pack(fill=tk.X)
        ttk.Button(actions, text="Assign to Analyst", command=lambda: self.assign_alert(alert, w)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Create Case", command=lambda: self.create_case_from_alert(alert, w)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Open Mail to Notify", command=lambda: self.open_mail(alert)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Auto-Isolate (Simulated)", command=lambda: self.autoremediate(alert, w)).pack(side=tk.LEFT, padx=4)

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
        frame = self.predict_tab
        header = ttk.Frame(frame, padding=8)
        header.pack(fill=tk.X)
        ttk.Label(header, text="Predict Risk from Manual Input", font=self.title_font).pack(side=tk.LEFT)
        gen_btn = ttk.Button(header, text="Simulate Event Now", command=self.manual_simulate_event)
        gen_btn.pack(side=tk.RIGHT)

        content = ttk.Frame(frame, padding=8)
        content.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(content)
        left.pack(side=tk.LEFT, fill=tk.Y, padx=8, pady=8)
        right = ttk.Frame(content)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=8, pady=8)

        # Inputs
        ttk.Label(left, text="Select User:").pack(anchor="w")
        self.user_var = tk.StringVar()
        user_names = [f'{u["user_id"]} - {u["name"]}' for u in MOCK_USERS]
        self.user_combo = ttk.Combobox(left, values=user_names, state="readonly", textvariable=self.user_var)
        self.user_combo.current(0)
        self.user_combo.pack(fill=tk.X, pady=4)

        ttk.Label(left, text="Off-hours activity (0.0 - 1.0):").pack(anchor="w")
        self.off_hours_var = tk.DoubleVar(value=0.1)
        ttk.Scale(left, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.off_hours_var).pack(fill=tk.X, pady=4)

        ttk.Label(left, text="File downloads last 24h:").pack(anchor="w")
        self.downloads_var = tk.IntVar(value=2)
        ttk.Spinbox(left, from_=0, to=200, textvariable=self.downloads_var).pack(fill=tk.X, pady=4)

        ttk.Label(left, text="USB activity (0/1):").pack(anchor="w")
        self.usb_var = tk.IntVar(value=0)
        ttk.Checkbutton(left, text="USB used recently", variable=self.usb_var).pack(anchor="w", pady=4)

        ttk.Label(left, text="Unusual processes (count):").pack(anchor="w")
        self.unusual_var = tk.IntVar(value=0)
        ttk.Spinbox(left, from_=0, to=20, textvariable=self.unusual_var).pack(fill=tk.X, pady=4)

        ttk.Label(left, text="Message text (affects sentiment):").pack(anchor="w")
        self.msg_entry = tk.Text(left, height=5)
        self.msg_entry.insert(tk.END, "Everything is ok")
        self.msg_entry.pack(fill=tk.X, pady=4)

        ttk.Button(left, text="Compute Risk", command=self.compute_manual_risk).pack(pady=6)

        # Right: show score, contributions
        ttk.Label(right, text="Prediction Output", font=self.header_font).pack(anchor="w")
        self.pred_score_lbl = ttk.Label(right, text="Score: N/A", font=self.header_font)
        self.pred_score_lbl.pack(anchor="w", pady=4)
        self.pred_explain = tk.Text(right, height=10)
        self.pred_explain.pack(fill=tk.BOTH, expand=True)

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
        self.pred_score_lbl.config(text=f"Score: {score:.3f} ({human_readable_score(score)})")
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
        frame = self.inbox_tab
        top = ttk.Frame(frame, padding=8)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Inbox / Sentiment Analyzer", font=self.title_font).pack(side=tk.LEFT)
        ttk.Button(top, text="Run Sentiment Scan", command=self.run_sentiment_scan).pack(side=tk.RIGHT)

        content = ttk.Frame(frame, padding=8)
        content.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(content, width=450)
        left.pack(side=tk.LEFT, fill=tk.Y)
        right = ttk.Frame(content)
        right.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Inbox list
        self.inbox_tree = ttk.Treeview(left, columns=("msg", "user", "sentiment", "ts"), show="headings", height=20)
        for c in ("msg", "user", "sentiment", "ts"):
            self.inbox_tree.heading(c, text=c.title())
            self.inbox_tree.column(c, width=120)
        self.inbox_tree.pack(fill=tk.Y, expand=True)
        self.inbox_tree.bind("<Double-1>", self.on_message_open)

        # Right: message detail and actions
        ttk.Label(right, text="Message Detail", font=self.header_font).pack(anchor="w")
        self.msg_detail = tk.Text(right, height=8)
        self.msg_detail.pack(fill=tk.X)
        self.msg_sentiment_label = ttk.Label(right, text="Sentiment: N/A", font=self.header_font)
        self.msg_sentiment_label.pack(anchor="w", pady=4)

        ttk.Button(right, text="Flag & Create Alert", command=self.flag_message_create_alert).pack(pady=6)
        ttk.Button(right, text="Open in Browser (Docs)", command=lambda: webbrowser.open("https://example.com/policies")).pack()

        self.run_sentiment_scan()

    def run_sentiment_scan(self):
        # Build inbox from recent events
        self.inbox_tree.delete(*self.inbox_tree.get_children())
        # show last 50 messages
        msgs = EVENT_STORE[-50:]
        for m in reversed(msgs):
            s = m["sentiment"]
            tag = "pos" if s > 0 else ("neg" if s < 0 else "neu")
            display_text = (m["message"][:40] + "...") if len(m["message"])>40 else m["message"]
            self.inbox_tree.insert("", tk.END, values=(display_text, m["user_name"], f"{s:.2f}", m["timestamp"].strftime("%Y-%m-%d %H:%M:%S")), tags=(tag,))

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
            self.msg_sentiment_label.config(text=f"Sentiment: {ev['sentiment']:.2f}")

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
        frame = self.actions_tab
        top = ttk.Frame(frame, padding=8)
        top.pack(fill=tk.X)
        ttk.Label(top, text="Automated Actions & Cases", font=self.title_font).pack(side=tk.LEFT)
        ttk.Button(top, text="Refresh", command=self.refresh_actions).pack(side=tk.RIGHT)
        content = ttk.Frame(frame, padding=8)
        content.pack(fill=tk.BOTH, expand=True)

        left = ttk.Frame(content)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(content, width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        # Cases Tree
        cols = ("case_id", "alert_id", "user", "dept", "score", "status", "created_at")
        self.cases_tree = ttk.Treeview(left, columns=cols, show="headings", height=18)
        for c in cols:
            self.cases_tree.heading(c, text=c.replace("_", " ").title())
            self.cases_tree.column(c, width=120)
        self.cases_tree.pack(fill=tk.BOTH, expand=True)
        self.cases_tree.bind("<Double-1>", self.on_case_open)

        # Right: audit + controls
        ttk.Label(right, text="Auto Action Controls", font=self.header_font).pack(anchor="w", pady=6, padx=6)
        ttk.Checkbutton(right, text="Enable Auto-Remediation", variable=self.auto_action_enabled).pack(anchor="w", padx=6)
        ttk.Label(right, text="Auto Threshold (>=)", font=self.header_font).pack(anchor="w", padx=6, pady=(10,0))
        ttk.Scale(right, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.auto_threshold).pack(fill=tk.X, padx=6)
        ttk.Button(right, text="Run Auto Action Sweep", command=self.run_auto_sweep).pack(padx=6, pady=8)
        ttk.Label(right, text="Audit Log (last 20):", font=self.header_font).pack(anchor="w", padx=6, pady=(10,0))
        self.actions_audit = tk.Text(right, height=12)
        self.actions_audit.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        self.refresh_actions()

    def refresh_actions(self):
        # refresh cases
        for i in self.cases_tree.get_children():
            self.cases_tree.delete(i)
        for c in sorted(CASES, key=lambda x: x["created_at"], reverse=True):
            self.cases_tree.insert("", tk.END, values=(
                c["case_id"],
                c["alert_id"],
                c["user_name"],
                c["dept"],
                f"{c['score']:.2f}",
                c["status"],
                c["created_at"].strftime("%Y-%m-%d %H:%M:%S")
            ))
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
        f = self.gamify_tab
        header = ttk.Frame(f, padding=8)
        header.pack(fill=tk.X)
        ttk.Label(header, text="Gamification & Challenges", font=self.title_font).pack(side=tk.LEFT)
        ttk.Button(header, text="Refresh", command=self.refresh_gamify).pack(side=tk.RIGHT)

        content = ttk.Frame(f, padding=8)
        content.pack(fill=tk.BOTH, expand=True)
        left = ttk.Frame(content)
        left.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        right = ttk.Frame(content, width=300)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        # Leaderboard
        ttk.Label(left, text="Leaderboard", font=self.header_font).pack(anchor="w")
        self.lb_tree = ttk.Treeview(left, columns=("user", "points"), show="headings", height=12)
        self.lb_tree.heading("user", text="User")
        self.lb_tree.heading("points", text="Points")
        self.lb_tree.pack(fill=tk.BOTH, expand=True)

        # Challenge: Simulated sandbox where analyst triages fake alerts
        ttk.Label(right, text="Sandbox Challenge", font=self.header_font).pack(anchor="w", pady=(4,0))
        ttk.Button(right, text="Start Sandbox (5 simulated alerts)", command=self.start_sandbox).pack(padx=6, pady=6)
        self.sandbox_log = tk.Text(right, height=18)
        self.sandbox_log.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.refresh_gamify()

    def refresh_gamify(self):
        # populate leaderboard from USER_POINTS
        for i in self.lb_tree.get_children():
            self.lb_tree.delete(i)
        sorted_users = sorted(USER_POINTS.items(), key=lambda x: x[1], reverse=True)
        for uid, pts in sorted_users:
            name = next((u["name"] for u in MOCK_USERS if u["user_id"]==uid), uid)
            self.lb_tree.insert("", tk.END, values=(name, pts))

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
        f = self.settings_tab
        ttk.Label(f, text="Settings & Configuration", font=self.title_font).pack(anchor="w", pady=8, padx=8)
        ttk.Label(f, text="Auto Remediation").pack(anchor="w", padx=16)
        ttk.Checkbutton(f, text="Enable Auto Remediation", variable=self.auto_action_enabled).pack(anchor="w", padx=32)
        ttk.Label(f, text="Auto threshold:").pack(anchor="w", padx=16, pady=(8,0))
        ttk.Scale(f, from_=0.0, to=1.0, orient=tk.HORIZONTAL, variable=self.auto_threshold).pack(fill=tk.X, padx=32)
        ttk.Button(f, text="Open Policy Docs (Browser)", command=lambda: webbrowser.open("https://example.com/policies")).pack(pady=12, padx=16)

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
