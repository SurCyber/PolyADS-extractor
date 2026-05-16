import sys
import os
import subprocess
import pandas as pd
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit,
    QFileDialog, QTextEdit, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTableWidget,
    QTableWidgetItem, QMessageBox, QProgressBar,
    QTabWidget, QListWidget, QListWidgetItem, QAbstractItemView,
    QSizePolicy, QFrame
)
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtCore import Qt, QThread, pyqtSignal


# ──────────────────────────────────────────────────────────────
#  Worker – ADS / Anti-Forensic scan
# ──────────────────────────────────────────────────────────────

class ScanWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, input_path, output_path):
        super().__init__()
        self.input_path  = input_path
        self.output_path = output_path

    def run(self):
        self.log_signal.emit("[*] Starting Deep Inspector...\n")

        process = subprocess.Popen(
            ["python", "backend.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        process.stdin.write(self.input_path  + "\n")
        process.stdin.write(self.output_path + "\n")
        process.stdin.flush()

        for line in process.stdout:
            self.log_signal.emit(line)

        process.wait()
        self.log_signal.emit("\n[OK] Scan completed\n")
        self.finished_signal.emit()


# ──────────────────────────────────────────────────────────────
#  Worker – VirusTotal hash lookup
# ──────────────────────────────────────────────────────────────

class VTScanWorker(QThread):
    log_signal      = pyqtSignal(str)
    finished_signal = pyqtSignal(list)   # emits list of result dicts

    def __init__(self, file_paths: list, api_key: str, output_dir: str):
        super().__init__()
        self.file_paths = file_paths
        self.api_key    = api_key
        self.output_dir = output_dir

    def run(self):
        # Import here so backend doesn't need PyQt6
        from backend import scan_files_virustotal

        self.log_signal.emit(
            f"[*] Starting VirusTotal scan for {len(self.file_paths)} file(s)...\n"
            f"[*] Free-tier rate limit: 4 requests/min "
            f"(15 s delay between lookups)\n\n"
        )

        results = scan_files_virustotal(
            file_paths   = self.file_paths,
            api_key      = self.api_key,
            output_dir   = self.output_dir,
            log_callback = self.log_signal.emit,
        )

        self.log_signal.emit("\n[OK] VirusTotal scan finished.\n")
        self.finished_signal.emit(results)


# ──────────────────────────────────────────────────────────────
#  Shared stylesheet
# ──────────────────────────────────────────────────────────────

THEME = """
QWidget {
    background-color: #f7f9fc;
    font-family: Segoe UI;
    font-size: 10pt;
    color: #1a1a1a;
}

QLabel {
    font-weight: 600;
}

QLineEdit {
    background-color: #ffffff;
    border: 1px solid #c7d2fe;
    border-radius: 4px;
    padding: 6px;
}
QLineEdit:focus {
    border: 1px solid #1f4fd8;
}

QPushButton {
    background-color: #1f4fd8;
    color: white;
    border-radius: 4px;
    padding: 6px 12px;
    font-weight: 600;
}
QPushButton:hover  { background-color: #3a66f0; }
QPushButton:pressed{ background-color: #163bb3; }

QPushButton#danger {
    background-color: #c0392b;
}
QPushButton#danger:hover  { background-color: #e74c3c; }
QPushButton#danger:pressed{ background-color: #96281b; }

QTextEdit {
    background-color: #ffffff;
    border: 1px solid #c7d2fe;
    border-radius: 4px;
}

QProgressBar {
    border: 1px solid #c7d2fe;
    border-radius: 5px;
    text-align: center;
    background-color: #ffffff;
}
QProgressBar::chunk { background-color: #1f77ff; }

QTableWidget {
    background-color: #ffffff;
    gridline-color: #e1e7ff;
}

QHeaderView::section {
    background-color: #e8efff;
    border: 1px solid #c7d2fe;
    font-weight: 600;
    padding: 4px;
}

QTreeWidget {
    background-color: #ffffff;
    border: 1px solid #c7d2fe;
}
QTreeWidget::item:selected {
    background-color: #dbe7ff;
    color: #000000;
}

QListWidget {
    background-color: #ffffff;
    border: 1px solid #c7d2fe;
    border-radius: 4px;
}
QListWidget::item:selected {
    background-color: #dbe7ff;
    color: #000000;
}

QTabWidget::pane {
    border: 1px solid #c7d2fe;
    border-radius: 4px;
    background: #f7f9fc;
}
QTabBar::tab {
    background: #e8efff;
    border: 1px solid #c7d2fe;
    border-bottom: none;
    padding: 6px 16px;
    font-weight: 600;
    border-top-left-radius: 4px;
    border-top-right-radius: 4px;
}
QTabBar::tab:selected {
    background: #ffffff;
    color: #1f4fd8;
}

QFrame#separator {
    background-color: #c7d2fe;
    max-height: 1px;
}
"""


# ──────────────────────────────────────────────────────────────
#  Tab 1 – ADS / Anti-Forensic Scanner
# ──────────────────────────────────────────────────────────────

class ADSScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self.input_path  = ""
        self.output_path = ""
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # Input
        in_row = QHBoxLayout()
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Select file or folder to scan")
        in_row.addWidget(QLabel("Input:"))
        in_row.addWidget(self.input_edit)
        in_row.addWidget(self._btn("📄 File",   self.select_file))
        in_row.addWidget(self._btn("📁 Folder", self.select_folder))
        layout.addLayout(in_row)

        # Output
        out_row = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select output directory")
        out_row.addWidget(QLabel("Output:"))
        out_row.addWidget(self.output_edit)
        out_row.addWidget(self._btn("📁 Output", self.select_output))
        layout.addLayout(out_row)

        # Progress + Scan button
        btn_row = QHBoxLayout()
        self.scan_btn = QPushButton("🚀 Start ADS Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        btn_row.addWidget(self.scan_btn)
        layout.addLayout(btn_row)

        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("Idle")
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        layout.addWidget(self.progress)

        # Log
        layout.addWidget(QLabel("Scan Log"))
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        self.log_box.setMaximumHeight(160)
        layout.addWidget(self.log_box)

        # Results table
        layout.addWidget(QLabel("Results"))
        self.table = QTableWidget()
        layout.addWidget(self.table)

        # Tree view
        layout.addWidget(QLabel("File → ADS Streams"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Item", "Risk Likelihood", "Indicators"])
        layout.addWidget(self.tree)

        # Open output
        layout.addWidget(self._btn("📂 Open Output Folder", self.open_output))

    # ── helpers ──────────────────────────────────────────────

    @staticmethod
    def _btn(label, slot):
        b = QPushButton(label)
        b.clicked.connect(slot)
        return b

    def select_file(self):
        path, _ = QFileDialog.getOpenFileName(self, "Select File")
        if path:
            self.input_path = path
            self.input_edit.setText(path)

    def select_folder(self):
        path = QFileDialog.getExistingDirectory(self, "Select Folder")
        if path:
            self.input_path = path
            self.input_edit.setText(path)

    def select_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if path:
            self.output_path = path
            self.output_edit.setText(path)

    def open_output(self):
        if self.output_path:
            os.startfile(self.output_path)

    # ── scan ─────────────────────────────────────────────────

    def start_scan(self):
        self.input_path  = self.input_edit.text().strip()
        self.output_path = self.output_edit.text().strip()

        if not self.input_path or not self.output_path:
            QMessageBox.warning(self, "Missing Input", "Select both input and output paths.")
            return

        os.makedirs(self.output_path, exist_ok=True)
        self.log_box.clear()
        self.tree.clear()
        self.table.clear()
        self.progress.setRange(0, 0)
        self.progress.setFormat("Scanning…")
        self.scan_btn.setEnabled(False)

        self.worker = ScanWorker(self.input_path, self.output_path)
        self.worker.log_signal.connect(self.log_box.insertPlainText)
        self.worker.finished_signal.connect(self.load_results)
        self.worker.start()

    def load_results(self):
        self.scan_btn.setEnabled(True)
        self.progress.setRange(0, 1)
        self.progress.setValue(1)
        self.progress.setFormat("Completed")

        csv_path = os.path.join(self.output_path, "report.csv")
        if not os.path.exists(csv_path):
            return

        df = pd.read_csv(csv_path)

        self.table.setRowCount(len(df))
        self.table.setColumnCount(len(df.columns))
        self.table.setHorizontalHeaderLabels(df.columns)

        for r, row in df.iterrows():
            for c, val in enumerate(row):
                item = QTableWidgetItem(str(val))
                if df.columns[c] == "Risk_Likelihood":
                    if val == "HIGH":
                        item.setBackground(QColor("#ffcccc"))
                    elif val == "MEDIUM":
                        item.setBackground(QColor("#fff2cc"))
                    elif val == "LOW":
                        item.setBackground(QColor("#d9ead3"))
                self.table.setItem(r, c, item)

        grouped = {}
        for _, row in df.iterrows():
            grouped.setdefault(row["File"], []).append(row)

        for file, entries in grouped.items():
            root = QTreeWidgetItem([file])
            self.tree.addTopLevelItem(root)
            for e in entries:
                label = "Main File" if e["Stream"] == "<main>" else e["Stream"]
                child = QTreeWidgetItem([
                    label,
                    e["Risk_Likelihood"],
                    e["Risk_Indicators"]
                ])
                root.addChild(child)

        self.tree.expandAll()


# ──────────────────────────────────────────────────────────────
#  Tab 2 – VirusTotal Hash Scanner
# ──────────────────────────────────────────────────────────────

class VTScanTab(QWidget):
    def __init__(self):
        super().__init__()
        self._file_paths: list[str] = []
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        # ── API key ──────────────────────────────────────────
        api_row = QHBoxLayout()
        api_lbl = QLabel("VirusTotal API Key:")
        api_lbl.setFixedWidth(150)
        self.api_key_edit = QLineEdit()
        self.api_key_edit.setPlaceholderText("Paste your VirusTotal API key here")
        self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.toggle_key_btn = QPushButton("👁 Show")
        self.toggle_key_btn.setFixedWidth(75)
        self.toggle_key_btn.clicked.connect(self._toggle_key_visibility)
        api_row.addWidget(api_lbl)
        api_row.addWidget(self.api_key_edit)
        api_row.addWidget(self.toggle_key_btn)
        layout.addLayout(api_row)

        note = QLabel(
            "ℹ  Free API: 4 lookups / minute. "
            "A 15-second delay is applied automatically between requests."
        )
        note.setStyleSheet("color: #555; font-weight: normal; font-size: 9pt;")
        layout.addWidget(note)

        sep = QFrame()
        sep.setObjectName("separator")
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # ── File / Folder selection ───────────────────────────
        layout.addWidget(QLabel("Files to Scan"))

        file_btn_row = QHBoxLayout()
        file_btn_row.addWidget(self._btn("➕ Add File(s)",  self.add_files))
        file_btn_row.addWidget(self._btn("📁 Add Folder",   self.add_folder))
        file_btn_row.addWidget(self._btn("🗑 Remove Selected", self.remove_selected))
        clear_btn = QPushButton("✖ Clear All")
        clear_btn.setObjectName("danger")
        clear_btn.clicked.connect(self.clear_files)
        file_btn_row.addWidget(clear_btn)
        file_btn_row.addStretch()
        layout.addLayout(file_btn_row)

        self.file_list = QListWidget()
        self.file_list.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.file_list.setMinimumHeight(110)
        self.file_list.setMaximumHeight(160)
        layout.addWidget(self.file_list)

        self.file_count_lbl = QLabel("0 file(s) queued")
        self.file_count_lbl.setStyleSheet("font-weight: normal; color: #555;")
        layout.addWidget(self.file_count_lbl)

        sep2 = QFrame()
        sep2.setObjectName("separator")
        sep2.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep2)

        # ── Output directory ─────────────────────────────────
        out_row = QHBoxLayout()
        out_lbl = QLabel("Output Directory:")
        out_lbl.setFixedWidth(150)
        self.vt_output_edit = QLineEdit()
        self.vt_output_edit.setPlaceholderText("Where to save vt_report.csv")
        out_row.addWidget(out_lbl)
        out_row.addWidget(self.vt_output_edit)
        out_row.addWidget(self._btn("📁 Browse", self.select_vt_output))
        layout.addLayout(out_row)

        # ── Scan button + progress ────────────────────────────
        scan_row = QHBoxLayout()
        self.vt_scan_btn = QPushButton("🔍 Scan with VirusTotal")
        self.vt_scan_btn.clicked.connect(self.start_vt_scan)
        scan_row.addWidget(self.vt_scan_btn)
        open_btn = QPushButton("📂 Open Output Folder")
        open_btn.clicked.connect(self.open_vt_output)
        scan_row.addWidget(open_btn)
        layout.addLayout(scan_row)

        self.vt_progress = QProgressBar()
        self.vt_progress.setRange(0, 1)
        self.vt_progress.setValue(0)
        self.vt_progress.setFormat("Idle")
        layout.addWidget(self.vt_progress)

        # ── Log ───────────────────────────────────────────────
        layout.addWidget(QLabel("Scan Log"))
        self.vt_log = QTextEdit()
        self.vt_log.setReadOnly(True)
        self.vt_log.setMaximumHeight(160)
        layout.addWidget(self.vt_log)

        # ── Results table ─────────────────────────────────────
        layout.addWidget(QLabel("VirusTotal Results"))
        self.vt_table = QTableWidget()
        self.vt_table.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        layout.addWidget(self.vt_table)

    # ── helpers ──────────────────────────────────────────────

    @staticmethod
    def _btn(label, slot):
        b = QPushButton(label)
        b.clicked.connect(slot)
        return b

    def _toggle_key_visibility(self):
        if self.api_key_edit.echoMode() == QLineEdit.EchoMode.Password:
            self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            self.toggle_key_btn.setText("🙈 Hide")
        else:
            self.api_key_edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.toggle_key_btn.setText("👁 Show")

    def _refresh_count(self):
        n = len(self._file_paths)
        self.file_count_lbl.setText(f"{n} file(s) queued")

    # ── file management ───────────────────────────────────────

    def add_files(self):
        paths, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for p in paths:
            if p and p not in self._file_paths:
                self._file_paths.append(p)
                self.file_list.addItem(QListWidgetItem(p))
        self._refresh_count()

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if not folder:
            return
        for root, _, files in os.walk(folder):
            for f in files:
                fp = os.path.join(root, f)
                if fp not in self._file_paths:
                    self._file_paths.append(fp)
                    self.file_list.addItem(QListWidgetItem(fp))
        self._refresh_count()

    def remove_selected(self):
        for item in self.file_list.selectedItems():
            row = self.file_list.row(item)
            self.file_list.takeItem(row)
            if row < len(self._file_paths):
                self._file_paths.pop(row)
        self._refresh_count()

    def clear_files(self):
        self._file_paths.clear()
        self.file_list.clear()
        self._refresh_count()

    def select_vt_output(self):
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if path:
            self.vt_output_edit.setText(path)

    def _on_cell_double_clicked(self, item):
        col = item.column()
        if col < len(self._VT_COLUMNS) and self._VT_COLUMNS[col] == "VT_Link":
            import webbrowser
            url = item.text()
            if url.startswith("http"):
                webbrowser.open(url)

    def open_vt_output(self):
        p = self.vt_output_edit.text().strip()
        if p and os.path.isdir(p):
            os.startfile(p)

    # ── scan ─────────────────────────────────────────────────

    def start_vt_scan(self):
        api_key    = self.api_key_edit.text().strip()
        output_dir = self.vt_output_edit.text().strip()

        if not api_key:
            QMessageBox.warning(self, "API Key Missing",
                                "Please enter your VirusTotal API key.")
            return

        if not self._file_paths:
            QMessageBox.warning(self, "No Files",
                                "Add at least one file to scan.")
            return

        if not output_dir:
            QMessageBox.warning(self, "No Output Directory",
                                "Please select an output directory.")
            return

        os.makedirs(output_dir, exist_ok=True)
        self.vt_log.clear()
        self.vt_table.clear()
        self.vt_table.setRowCount(0)
        self.vt_progress.setRange(0, 0)
        self.vt_progress.setFormat("Scanning…")
        self.vt_scan_btn.setEnabled(False)

        self.vt_worker = VTScanWorker(
            file_paths = list(self._file_paths),
            api_key    = api_key,
            output_dir = output_dir,
        )
        self.vt_worker.log_signal.connect(self.vt_log.insertPlainText)
        self.vt_worker.finished_signal.connect(self._load_vt_results)
        self.vt_worker.start()

    # ── populate results table ────────────────────────────────

    _VT_COLUMNS = [
        # Identity
        "File", "SHA256", "MD5", "SHA1",
        "Meaningful_Name", "Known_Names", "File_Size",
        "Type_Description", "Magic", "Type_Tag",
        # Detection
        "Found_in_VT", "Verdict",
        "Malicious", "Suspicious", "Harmless", "Undetected",
        "Timeout", "Failures", "Total_Engines",
        # Reputation
        "VT_Reputation", "Community_Malicious", "Community_Harmless",
        # Threat
        "Threat_Label", "Threat_Category", "Threat_Name", "Tags",
        # Timeline
        "First_Submitted", "Last_Submitted", "Last_Analyzed",
        "Times_Submitted", "Unique_Sources",
        # Sigma
        "Sigma_Critical", "Sigma_High", "Sigma_Medium", "Sigma_Low",
        # IDS
        "IDS_High", "IDS_Medium", "IDS_Low", "IDS_High_Alerts",
        # Sandbox
        "Sandbox_Summary",
        # PE / Packer
        "Imphash", "Authentihash", "Compiler_Packer", "TrID_Top",
        # Links
        "VT_Link", "Error",
    ]

    # Verdict → background colour
    _VERDICT_COLORS = {
        "MALICIOUS":   "#ffcccc",
        "SUSPICIOUS":  "#fff2cc",
        "CLEAN":       "#d9ead3",
        "NOT FOUND":   "#e8e8e8",
        "RATE LIMITED":"#ffe0b2",
        "AUTH ERROR":  "#f8bbd0",
        "ERROR":       "#f8bbd0",
    }

    def _load_vt_results(self, results: list):
        self.vt_scan_btn.setEnabled(True)
        self.vt_progress.setRange(0, 1)
        self.vt_progress.setValue(1)
        self.vt_progress.setFormat("Completed")

        if not results:
            self.vt_log.append("[!] No results returned.\n")
            return

        cols = self._VT_COLUMNS
        self.vt_table.setColumnCount(len(cols))
        self.vt_table.setHorizontalHeaderLabels(cols)
        self.vt_table.setRowCount(len(results))

        for r, row in enumerate(results):
            # Determine row colour from verdict first
            verdict_val = str(row.get("Verdict", ""))
            row_colour  = self._VERDICT_COLORS.get(verdict_val, "#ffffff")

            for c, col in enumerate(cols):
                val  = str(row.get(col, ""))
                cell = QTableWidgetItem(val)
                cell.setBackground(QColor(row_colour))

                # Bold red text for non-zero malicious count
                if col == "Malicious":
                    try:
                        if int(val) > 0:
                            cell.setForeground(QColor("#c0392b"))
                            f = cell.font()
                            f.setBold(True)
                            cell.setFont(f)
                    except ValueError:
                        pass

                # Bold red text for sigma/IDS high counts
                if col in ("Sigma_High", "Sigma_Critical", "IDS_High"):
                    try:
                        if int(val) > 0:
                            cell.setForeground(QColor("#c0392b"))
                            f = cell.font()
                            f.setBold(True)
                            cell.setFont(f)
                    except ValueError:
                        pass

                # Clickable VT link hint
                if col == "VT_Link" and val.startswith("http"):
                    cell.setForeground(QColor("#1f4fd8"))
                    f = cell.font()
                    f.setUnderline(True)
                    cell.setFont(f)
                    cell.setToolTip("Double-click to open in browser")

                self.vt_table.setItem(r, c, cell)

        self.vt_table.resizeColumnsToContents()
        self.vt_table.setColumnWidth(self._VT_COLUMNS.index("IDS_High_Alerts"),  260)
        self.vt_table.setColumnWidth(self._VT_COLUMNS.index("Sandbox_Summary"),  200)
        self.vt_table.setColumnWidth(self._VT_COLUMNS.index("Tags"),             200)
        self.vt_table.setColumnWidth(self._VT_COLUMNS.index("File"),             220)
        self.vt_table.itemDoubleClicked.connect(self._on_cell_double_clicked)
        self.vt_log.append(
            f"\n[+] Table populated with {len(results)} result(s).\n"
        )


# ──────────────────────────────────────────────────────────────
#  Main window
# ──────────────────────────────────────────────────────────────

class PolyADSUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Deep Inspector – Anti-Forensic & VirusTotal Detection")
        self.resize(1150, 820)
        self._build_ui()
        self.setStyleSheet(THEME)

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)

        # Header
        header = QLabel("🔬  Deep Inspector")
        header.setStyleSheet(
            "font-size: 16pt; font-weight: 700; color: #1f4fd8; padding: 4px 0;"
        )
        root.addWidget(header)

        # Tabs
        tabs = QTabWidget()
        self.ads_tab = ADSScanTab()
        self.vt_tab  = VTScanTab()
        tabs.addTab(self.ads_tab, "🛡  ADS / Anti-Forensic Scanner")
        tabs.addTab(self.vt_tab,  "🦠  VirusTotal Hash Scanner")
        root.addWidget(tabs)


# ──────────────────────────────────────────────────────────────
#  Entry point
# ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PolyADSUI()
    win.show()
    sys.exit(app.exec())