import sys
import psutil
import platform
import hashlib
import threading
import webbrowser
import os
import json
import datetime
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QWidget, QTableWidget, QTableWidgetItem, QVBoxLayout,
    QPushButton, QHBoxLayout, QLabel, QDialog, QDialogButtonBox, QHeaderView,
    QProgressBar, QSizePolicy, QFrame, QGridLayout, QFileDialog, QMessageBox,
    QSpacerItem
)
from PyQt5.QtGui import QColor, QFont, QIcon
from PyQt5.QtCore import Qt, QTimer

# ------------------------------
# Config / App constants
# ------------------------------

APP_NAME = 'Keyloggers'
ICON_FILE = 'icon.png'
try:
    CONFIG_FILE = str(Path(__file__).parent.joinpath('config.json'))
except NameError:
    CONFIG_FILE = 'config.json'

# ------------------------------
# Detection heuristics (unchanged)
# ------------------------------

MALWARE_KEYWORDS = [
    'keylog', 'logger', 'keyboard', 'input', 'intercept', 'hook', 'capture',
    'stealer', 'grabber', 'dump', 'inject', 'backdoor', 'rootkit', 'trojan',
    'rat', 'miner', 'botnet', 'ransomware', 'crypter', 'payload', 'exploit'
]

SUSPICIOUS_PATHS = [
    'temp', 'tmp', 'appdata', 'local', 'roaming', 'programdata', 'windows/temp',
    'users/public', 'recycle', '$recycle.bin', 'system32/drivers', '/tmp',
    '/var/tmp', '/dev/shm', '.cache', '.local/share', '.config'
]

SYSTEM_PROCESSES = [
    'system', 'init', 'kernel', 'explorer', 'svchost', 'services', 'winlogon',
    'csrss', 'smss', 'wininit', 'lsass', 'spoolsv', 'dwm', 'taskhost',
    'systemd', 'kthreadd', 'ksoftirqd', 'migration', 'rcu_gp'
]

NETWORK_SUSPICIOUS_PORTS = [
    1337, 31337, 4444, 5555, 6666, 7777, 8080, 9999, 12345, 54321,
    6667, 6697, 1234, 3389, 5900, 8888, 9090
]

# ------------------------------
# Utilities
# ------------------------------

def safe_sha256(path: str) -> str:
    try:
        with open(path, 'rb') as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(8192), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def get_process_info(proc: psutil.Process):
    try:
        pid = proc.pid
        name = proc.name()
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = ''
        return pid, name, exe
    except Exception:
        return None, None, None


def analyze_process_behavior(proc: psutil.Process):
    score = 0
    reasons = []
    try:
        pid, name, exe = get_process_info(proc)
        if not name:
            return score, reasons
        name_lower = name.lower()
        exe_lower = exe.lower() if exe else ''
        for keyword in MALWARE_KEYWORDS:
            if keyword in name_lower or keyword in exe_lower:
                score += 8
                reasons.append(f"Contains suspicious keyword: {keyword}")
        if exe:
            for pathpart in SUSPICIOUS_PATHS:
                if pathpart in exe_lower:
                    score += 6
                    reasons.append(f"Runs from suspicious location: {pathpart}")
        is_system = any(sys_proc in name_lower for sys_proc in SYSTEM_PROCESSES)
        if not is_system and exe:
            try:
                stat = os.stat(exe)
                creation_time = getattr(stat, 'st_ctime', 0)
                if creation_time and (datetime.datetime.now().timestamp() - creation_time) < 86400:
                    score += 4
                    reasons.append("Recently created executable")
                if stat.st_size < 50_000:
                    score += 3
                    reasons.append("Unusually small executable")
                elif stat.st_size > 50_000_000:
                    score += 2
                    reasons.append("Unusually large executable")
            except Exception:
                pass
        try:
            for conn in proc.connections(kind='inet'):
                if getattr(conn, 'raddr', None) and conn.status != psutil.CONN_LISTEN:
                    score += 5
                    reasons.append(f"Active network connection to {getattr(conn.raddr,'ip','')}:{getattr(conn.raddr,'port','')}")
                    if getattr(conn, 'raddr', None) and conn.raddr.port in NETWORK_SUSPICIOUS_PORTS:
                        score += 8
                        reasons.append(f"Connection to suspicious port: {conn.raddr.port}")
        except Exception:
            pass
        try:
            mem = proc.memory_info()
            if mem.rss > 500 * 1024 * 1024:
                score += 2
                reasons.append("High memory usage")
        except Exception:
            pass
        try:
            cpu_percent = proc.cpu_percent(interval=0.05)
            if cpu_percent > 80:
                score += 3
                reasons.append("High CPU usage")
        except Exception:
            pass
        try:
            same_name_count = sum(1 for p in psutil.process_iter(['name']) if (p.info.get('name') or '').lower() == name_lower)
            if same_name_count > 3:
                score += 4
                reasons.append(f"Multiple instances running ({same_name_count})")
        except Exception:
            pass
        if platform.system() == 'Linux':
            try:
                for f in proc.open_files():
                    p = f.path
                    if '/dev/input' in p:
                        score += 10
                        reasons.append("Accesses keyboard input devices")
                    elif '/proc/' in p and 'mem' in p:
                        score += 6
                        reasons.append("Accesses process memory")
            except Exception:
                pass
        elif platform.system() == 'Windows':
            try:
                if exe_lower and any(h in exe_lower for h in ['hook', 'inject', 'dll']):
                    score += 7
                    reasons.append("Potential hooking/injection capabilities")
            except Exception:
                pass
    except Exception:
        pass
    return score, reasons


def scan_for_threats():
    flagged = []
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid, name, exe = get_process_info(proc)
            if not name:
                continue
            score, reasons = analyze_process_behavior(proc)
            if score > 0:
                if score >= 15:
                    level = 'CRITICAL'
                elif score >= 10:
                    level = 'HIGH'
                elif score >= 5:
                    level = 'MEDIUM'
                else:
                    level = 'LOW'
                flagged.append({
                    'pid': pid,
                    'name': name,
                    'exe': exe,
                    'hash': safe_sha256(exe) if exe else '',
                    'score': score,
                    'threat_level': level,
                    'reasons': '; '.join(reasons) if reasons else 'Suspicious behavior detected'
                })
        except Exception:
            continue
    flagged.sort(key=lambda x: x['score'], reverse=True)
    return flagged


# ------------------------------
# Startup helpers
# ------------------------------

def get_startup_programs_windows():
    try:
        import winreg
    except ImportError:
        return []
    locations = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),
    ]
    entries = []
    for root, path in locations:
        try:
            reg = winreg.OpenKey(root, path)
            for i in range(0, winreg.QueryInfoKey(reg)[1]):
                name, value, _type = winreg.EnumValue(reg, i)
                entries.append((name, value))
        except Exception:
            continue
    return entries


def get_autostart_linux():
    import glob
    autostart_files = []
    user_config = os.path.expanduser('~/.config/autostart')
    if os.path.isdir(user_config):
        autostart_files.extend(glob.glob(os.path.join(user_config, '*.desktop')))
    system_paths = ['/etc/xdg/autostart/', '/usr/share/applications/']
    for path in system_paths:
        if os.path.isdir(path):
            autostart_files.extend(glob.glob(os.path.join(path, '*.desktop')))
    return autostart_files


# ------------------------------
# Theme manager (QSS)
# ------------------------------

class ThemeManager:
    def __init__(self):
        self.theme = 'dark'
        self.load()

    def load(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.theme = data.get('theme', 'dark')
        except Exception:
            self.theme = 'dark'

    def save(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump({'theme': self.theme}, f, indent=2)
        except Exception:
            pass

    def apply(self, widget: QWidget):
        if self.theme == 'light':
            widget.setStyleSheet(self.light_qss())
        else:
            widget.setStyleSheet(self.dark_qss())

    def toggle(self, widget: QWidget):
        self.theme = 'light' if self.theme == 'dark' else 'dark'
        self.apply(widget)
        self.save()

    def dark_qss(self) -> str:
        return (
            """
            QWidget { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #0a0f17, stop:0.35 #0e1521, stop:0.7 #0c1420, stop:1 #0a0f17); color: #E6F1FF; font-family: 'Segoe UI', 'Consolas', monospace; }
            QFrame[role='card'] { border: 2px solid #00AAFF; border-radius: 16px; background: rgba(0, 34, 68, 0.12); margin: 6px; }
            QFrame[role='cardRed'] { border: 2px solid #FF4444; border-radius: 16px; background: rgba(68, 0, 0, 0.12); margin: 6px; }
            QFrame[role='cardGreen'] { border: 2px solid #00FF88; border-radius: 16px; background: rgba(0, 68, 40, 0.12); margin: 6px; }
            QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 rgba(0,170,255,.14), stop:1 rgba(0,255,136,.12)); border: 2px solid rgba(0,170,255,.7); color: #E6F1FF; border-radius: 12px; padding: 10px 18px; font-weight: 600; }
            QPushButton:hover { border-color: #00FF88; }
            QPushButton:pressed { background: rgba(255,255,255,0.04); }
            QPushButton:disabled { color: rgba(230,241,255,0.4); border-color: rgba(255,255,255,0.2); background: rgba(255,255,255,0.03); }
            QPushButton#iconBtn { min-width:36px; min-height:36px; max-width:36px; max-height:36px; border-radius: 18px; padding:0; font-size:16px; color:#FFFFFF; background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.18); }
            QPushButton#iconBtn:hover { background: rgba(255,255,255,0.08); }
            QLabel#status { background: rgba(0, 255, 136, 0.06); border:1px solid rgba(0,255,136,.28); border-radius:10px; padding:10px; color:#B2FFE0; }
            QTableWidget { background: #0b111b; alternate-background-color: rgba(0,170,255,0.04); color: #E6F1FF; gridline-color: rgba(0,170,255,.25); border:2px solid #FF4444; border-radius:12px; }
            QHeaderView::section { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #ff6161, stop:1 #b82020); color: #FFFFFF; font-weight:700; border:none; padding:10px; }
            QTableWidget::item { border-bottom: 1px solid rgba(255,255,255,0.04); }
            QScrollBar:vertical { background: rgba(255,255,255,0.04); width: 10px; border-radius: 5px; }
            QScrollBar::handle:vertical { background: rgba(255,255,255,0.20); border-radius: 5px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background: rgba(255,255,255,0.34); }
            """
        )

    def light_qss(self) -> str:
        return (
            """
            QWidget { background: qlineargradient(x1:0,y1:0,x2:1,y2:1, stop:0 #f7fbff, stop:0.4 #f2f7fb, stop:1 #eef3f8); color: #0a1a2b; font-family: 'Segoe UI', 'Consolas', monospace; }
            QFrame[role='card'] { border: 2px solid #00AAFF; border-radius: 16px; background: rgba(0,170,255,0.06); margin: 6px; }
            QFrame[role='cardRed'] { border: 2px solid #FF4444; border-radius: 16px; background: rgba(255,68,68,0.06); margin: 6px; }
            QFrame[role='cardGreen'] { border: 2px solid #00C27A; border-radius: 16px; background: rgba(0,194,122,0.06); margin: 6px; }
            QPushButton { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 rgba(0,170,255,.08), stop:1 rgba(0,194,122,.08)); border: 2px solid rgba(0,170,255,.65); color: #0a1a2b; border-radius: 12px; padding: 10px 18px; font-weight: 600; }
            QPushButton:hover { border-color: #00C27A; }
            QPushButton:pressed { background: rgba(0,0,0,0.04); }
            QPushButton:disabled { color: rgba(10,26,43,0.35); border-color: rgba(10,26,43,0.2); background: rgba(10,26,43,0.04); }
            QPushButton#iconBtn { min-width:36px; min-height:36px; max-width:36px; max-height:36px; border-radius: 18px; padding:0; font-size:16px; color:#000000; background: rgba(0,0,0,0.06); border: 1px solid rgba(0,0,0,0.18); }
            QPushButton#iconBtn:hover { background: rgba(0,0,0,0.12); }
            QLabel#status { background: rgba(0, 194, 122, 0.08); border:1px solid rgba(0,194,122,.28); border-radius:10px; padding:10px; color:#07573b; }
            QTableWidget { background: #ffffff; alternate-background-color: rgba(0,170,255,0.04); color: #0a1a2b; gridline-color: rgba(10,26,43,.12); border:2px solid #FF4444; border-radius:12px; }
            QHeaderView::section { background: qlineargradient(x1:0,y1:0,x2:0,y2:1, stop:0 #ff6e6e, stop:1 #d93a3a); color: #ffffff; font-weight:700; border:none; padding:10px; }
            QTableWidget::item { border-bottom: 1px solid rgba(10,26,43,0.06); }
            QScrollBar:vertical { background: rgba(0,0,0,0.04); width: 10px; border-radius: 5px; }
            QScrollBar::handle:vertical { background: rgba(0,0,0,0.22); border-radius: 5px; min-height: 20px; }
            QScrollBar::handle:vertical:hover { background: rgba(0,0,0,0.36); }
            """
        )


# ------------------------------
# UI building blocks
# ------------------------------

class CyberpunkFrame(QFrame):
    def __init__(self, role='card'):
        super().__init__()
        self.setProperty('role', role)


class StatusLabel(QLabel):
    def __init__(self, text=''):
        super().__init__(text)
        self.setObjectName('status')
        self.setAlignment(Qt.AlignVCenter)


class ThreatTable(QTableWidget):
    def __init__(self):
        super().__init__(0, 7)
        self.setup_table()

    def setup_table(self):
        self.setHorizontalHeaderLabels(["PID", "PROCESS", "PATH", "SHA256", "SCORE", "THREAT LEVEL", "DETAILS"])
        h = self.horizontalHeader()
        h.setSectionResizeMode(QHeaderView.Stretch)
        h.setSectionResizeMode(2, QHeaderView.Interactive)
        h.setSectionResizeMode(3, QHeaderView.Interactive)
        h.setSectionResizeMode(6, QHeaderView.Interactive)
        self.verticalHeader().setVisible(False)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setAlternatingRowColors(True)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)


# ------------------------------
# Main application
# ------------------------------

class MalwareDetectorApp(QWidget):
    def __init__(self):
        super().__init__()
        self.threats = []
        self.scan_thread = None
        self.theme = ThemeManager()
        if os.path.exists(ICON_FILE):
            self.setWindowIcon(QIcon(ICON_FILE))
        self.setup_ui()
        # apply theme after widgets exist
        self.theme.apply(self)

    def setup_ui(self):
        self.setWindowTitle(APP_NAME)
        self.resize(1200, 820)

        main_layout = QVBoxLayout()
        main_layout.setSpacing(14)
        main_layout.setContentsMargins(14, 14, 14, 14)

        # Header
        header = CyberpunkFrame('card')
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(16, 12, 16, 12)

        lbl_title = QLabel(APP_NAME.upper())
        lbl_title.setStyleSheet("font-size:26px; font-weight:800; letter-spacing:3px; color:#FF4C4C;")
        lbl_sub = QLabel('Advanced Malware Detection & System Analysis')
        lbl_sub.setStyleSheet('font-size:13px; opacity:0.85;')
        title_col = QVBoxLayout()
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_sub)
        h_layout.addLayout(title_col)
        h_layout.addItem(QSpacerItem(20, 10, QSizePolicy.Expanding, QSizePolicy.Minimum))

        # About + Theme buttons
        self.btn_about = QPushButton('ℹ️')
        self.btn_about.setObjectName('iconBtn')
        self.btn_about.setToolTip('About')
        self.btn_about.clicked.connect(self.show_about)
        self.btn_theme = QPushButton('🌙' if self.theme.theme == 'dark' else '☀️')
        self.btn_theme.setObjectName('iconBtn')
        self.btn_theme.setToolTip('Toggle Theme')
        self.btn_theme.clicked.connect(self.toggle_theme)
        h_layout.addWidget(self.btn_about)
        h_layout.addWidget(self.btn_theme)

        main_layout.addWidget(header)

        # Controls
        control = CyberpunkFrame('card')
        grid = QGridLayout(control)
        grid.setContentsMargins(16, 12, 16, 12)
        grid.setHorizontalSpacing(12)
        grid.setVerticalSpacing(12)

        self.btn_scan = QPushButton('SCAN SYSTEM')
        self.btn_report = QPushButton('GENERATE REPORT')
        self.btn_export = QPushButton('EXPORT DATA')
        self.btn_network = QPushButton('NETWORK ANALYSIS')
        self.btn_startup = QPushButton('STARTUP PROGRAMS')
        self.btn_clear = QPushButton('CLEAR RESULTS')

        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_report.clicked.connect(self.generate_report)
        self.btn_export.clicked.connect(self.export_data)
        self.btn_network.clicked.connect(self.show_network_analysis)
        self.btn_startup.clicked.connect(self.show_startup_analysis)
        self.btn_clear.clicked.connect(self.clear_results)

        grid.addWidget(self.btn_scan, 0, 0)
        grid.addWidget(self.btn_report, 0, 1)
        grid.addWidget(self.btn_export, 0, 2)
        grid.addWidget(self.btn_network, 1, 0)
        grid.addWidget(self.btn_startup, 1, 1)
        grid.addWidget(self.btn_clear, 1, 2)

        main_layout.addWidget(control)

        # Progress
        progress_card = CyberpunkFrame('cardGreen')
        pv = QVBoxLayout(progress_card)
        pv.setContentsMargins(16, 12, 16, 12)
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setMinimumHeight(18)
        pv.addWidget(self.progress_bar)
        main_layout.addWidget(progress_card)

        # Results
        results_card = CyberpunkFrame('cardRed')
        rv = QVBoxLayout(results_card)
        rv.setContentsMargins(16, 12, 16, 12)
        title = QLabel('THREAT ANALYSIS RESULTS')
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet('font-size:18px; font-weight:800; letter-spacing:2px; color:#FF4C4C;')
        rv.addWidget(title)
        self.threat_table = ThreatTable()
        self.threat_table.setMinimumHeight(420)
        rv.addWidget(self.threat_table)
        main_layout.addWidget(results_card)

        # Status
        status_card = CyberpunkFrame('card')
        sh = QHBoxLayout(status_card)
        sh.setContentsMargins(16, 12, 16, 12)
        self.status_label = StatusLabel('SYSTEM READY - AWAITING COMMANDS')
        sh.addWidget(self.status_label)
        main_layout.addWidget(status_card)

        self.setLayout(main_layout)

    # ---------- Theme handlers ----------
    def toggle_theme(self):
        self.theme.toggle(self)
        # update unicode icon: white sun in dark; black moon in light
        self.btn_theme.setText('🌙' if self.theme.theme == 'dark' else '☀️')

    # ---------- About ----------
    def show_about(self):
        dlg = QDialog(self)
        dlg.setWindowTitle(f'About {APP_NAME}')
        if os.path.exists(ICON_FILE):
            dlg.setWindowIcon(QIcon(ICON_FILE))
        v = QVBoxLayout(dlg)
        label = QLabel(f"<b>{APP_NAME}</b><br>Advanced malware detection & behavioral analysis.<br>Real-time heuristics, network inspection, startup auditing.")
        label.setWordWrap(True)
        v.addWidget(label)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        v.addWidget(btns)
        # style dialog to match theme
        if self.theme.theme == 'dark':
            dlg.setStyleSheet(self.theme.dark_qss())
        else:
            dlg.setStyleSheet(self.theme.light_qss())
        dlg.exec_()

    # ---------- Scan workflow ----------
    def start_scan(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.update_status('SCAN ALREADY IN PROGRESS - PLEASE WAIT')
            return
        self.update_status('INITIATING DEEP SYSTEM SCAN...')
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(0)
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()

    def run_scan(self):
        try:
            self.threats = scan_for_threats()
            QTimer.singleShot(0, self.scan_complete)
        except Exception as e:
            QTimer.singleShot(0, lambda: self.scan_error(str(e)))

    def scan_complete(self):
        self.progress_bar.setVisible(False)
        self.update_table()
        if self.threats:
            critical_count = sum(1 for t in self.threats if t['threat_level'] == 'CRITICAL')
            high_count = sum(1 for t in self.threats if t['threat_level'] == 'HIGH')
            if critical_count > 0:
                self.update_status(f'⚠ CRITICAL: {len(self.threats)} THREATS - {critical_count} CRITICAL, {high_count} HIGH')
            else:
                self.update_status(f'SCAN COMPLETE: {len(self.threats)} POTENTIAL THREATS DETECTED')
        else:
            self.update_status('SCAN COMPLETE: NO THREATS DETECTED - SYSTEM CLEAN')

    def scan_error(self, error):
        self.progress_bar.setVisible(False)
        self.update_status(f'SCAN ERROR: {error}')

    def update_table(self):
        self.threat_table.setRowCount(len(self.threats))
        for row, t in enumerate(self.threats):
            items = [str(t['pid']), t['name'], t['exe'] or 'N/A', t.get('hash',''), str(t['score']), t['threat_level'], t['reasons']]
            for col, text in enumerate(items):
                item = QTableWidgetItem(text)
                level = t['threat_level']
                if level == 'CRITICAL':
                    item.setForeground(QColor('#FF8A8A'))
                elif level == 'HIGH':
                    item.setForeground(QColor('#FFD18A'))
                elif level == 'MEDIUM':
                    item.setForeground(QColor('#E2F7A7'))
                else:
                    item.setForeground(QColor('#BFD6FF'))
                self.threat_table.setItem(row, col, item)

    # ---------- Export & reporting ----------
    def export_data(self):
        if not self.threats:
            QMessageBox.information(self, 'Export', 'No results to export yet.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export CSV', f'Keyloggers_Data_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.csv', 'CSV Files (*.csv)')
        if not path:
            return
        try:
            import csv
            with open(path, 'w', newline='', encoding='utf-8') as f:
                w = csv.writer(f)
                w.writerow(['PID','Process','Path','SHA256','Score','Threat Level','Details'])
                for t in self.threats:
                    w.writerow([t['pid'], t['name'], t['exe'], t.get('hash',''), t['score'], t['threat_level'], t['reasons']])
            QMessageBox.information(self, 'Export', f'CSV exported to:\n{path}')
        except Exception as e:
            QMessageBox.critical(self, 'Export Error', str(e))

    def generate_report(self):
        if not self.threats:
            QMessageBox.information(self, 'Report', 'No results to include in report.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save HTML Report', f'Keyloggers_Report_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.html', 'HTML Files (*.html)')
        if not path:
            return
        try:
            html = [
                "<html><head><meta charset='utf-8'><title>Keyloggers Report</title>",
                "<style>body{font-family:Segoe UI,Roboto,Arial;background:#fff;color:#1d2330;padding:20px} th,td{border:1px solid #e0e0e0;padding:8px;} th{background:#ffe3e3;color:#111;text-transform:uppercase;font-weight:700;} tr:nth-child(even){background:#fafafa}</style></head><body>",
                f"<h1>Keyloggers - Threat Report</h1><p>Generated: {datetime.datetime.now().isoformat(' ', 'seconds')}</p>",
                "<table><tr><th>PID</th><th>Process</th><th>Path</th><th>SHA256</th><th>Score</th><th>Level</th><th>Details</th></tr>"
            ]
            for t in self.threats:
                exe = (t['exe'] or 'N/A').replace('&','&amp;')
                html.append(f"<tr><td>{t['pid']}</td><td>{t['name']}</td><td>{exe}</td><td>{t.get('hash','')}</td><td>{t['score']}</td><td>{t['threat_level']}</td><td>{t['reasons']}</td></tr>")
            html.append('</table></body></html>')
            with open(path, 'w', encoding='utf-8') as f:
                f.write('\n'.join(html))
            QMessageBox.information(self, 'Report', f'HTML report saved to:\n{path}')
        except Exception as e:
            QMessageBox.critical(self, 'Report Error', str(e))

    # ---------- Dialogs ----------
    def _style_dialog_and_table(self, dlg: QDialog, table: QTableWidget):
        if self.theme.theme == 'light':
            dlg.setStyleSheet(self.theme.light_qss())
        else:
            dlg.setStyleSheet(self.theme.dark_qss())
        table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

    def show_network_analysis(self):
        rows = []
        try:
            for p in psutil.process_iter(['pid', 'name']):
                try:
                    for c in p.connections(kind='inet'):
                        laddr = f"{getattr(c.laddr, 'ip', '')}:{getattr(c.laddr, 'port', '')}" if getattr(c, 'laddr', None) else ''
                        raddr = f"{getattr(c.raddr, 'ip', '')}:{getattr(c.raddr, 'port', '')}" if getattr(c, 'raddr', None) else ''
                        flags = []
                        if getattr(c, 'raddr', None) and c.raddr.port in NETWORK_SUSPICIOUS_PORTS:
                            flags.append('⚠ suspicious port')
                        if c.status != psutil.CONN_LISTEN and getattr(c, 'raddr', None):
                            flags.append('active')
                        rows.append([p.info.get('pid'), p.info.get('name'), c.status, laddr, raddr, ', '.join(flags)])
                except Exception:
                    continue
        except Exception:
            pass
        dlg = QDialog(self)
        dlg.setWindowTitle('Network Analysis')
        if os.path.exists(ICON_FILE):
            dlg.setWindowIcon(QIcon(ICON_FILE))
        dlg.resize(980, 540)
        v = QVBoxLayout(dlg)
        wrap = CyberpunkFrame('card')
        inner = QVBoxLayout(wrap)
        inner.setContentsMargins(12, 12, 12, 12)
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(['PID','Process','State','Local','Remote','Flags'])
        for r in rows:
            row = table.rowCount()
            table.insertRow(row)
            for c, val in enumerate(r):
                table.setItem(row, c, QTableWidgetItem(str(val)))
        inner.addWidget(table)
        v.addWidget(wrap)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        v.addWidget(btns)
        self._style_dialog_and_table(dlg, table)
        dlg.exec_()

    def show_startup_analysis(self):
        entries = []
        if platform.system() == 'Windows':
            entries = get_startup_programs_windows()
        elif platform.system() == 'Linux':
            entries = [(Path(p).name, p) for p in get_autostart_linux()]
        else:
            QMessageBox.information(self, 'Startup', 'Startup enumeration not supported on this OS.')
            return
        dlg = QDialog(self)
        dlg.setWindowTitle('Startup Programs')
        if os.path.exists(ICON_FILE):
            dlg.setWindowIcon(QIcon(ICON_FILE))
        dlg.resize(900, 540)
        v = QVBoxLayout(dlg)
        wrap = CyberpunkFrame('card')
        inner = QVBoxLayout(wrap)
        inner.setContentsMargins(12, 12, 12, 12)
        table = QTableWidget(0, 2)
        table.setHorizontalHeaderLabels(['Name','Path/Command'])
        for name, val in entries:
            row = table.rowCount()
            table.insertRow(row)
            table.setItem(row, 0, QTableWidgetItem(str(name)))
            table.setItem(row, 1, QTableWidgetItem(str(val)))
        inner.addWidget(table)
        v.addWidget(wrap)
        btns = QDialogButtonBox(QDialogButtonBox.Close)
        btns.rejected.connect(dlg.reject)
        v.addWidget(btns)
        self._style_dialog_and_table(dlg, table)
        dlg.exec_()

    # ---------- Misc ----------
    def clear_results(self):
        self.threats = []
        self.threat_table.setRowCount(0)
        self.update_status('RESULTS CLEARED')

    def update_status(self, text: str):
        self.status_label.setText(text)


# ------------------------------
# Entrypoint
# ------------------------------

def main():
    app = QApplication(sys.argv)
    if os.path.exists(ICON_FILE):
        app.setWindowIcon(QIcon(ICON_FILE))
    w = MalwareDetectorApp()
    w.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
