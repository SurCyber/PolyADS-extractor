import sys
import os
import subprocess
import pandas as pd
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit,
    QFileDialog, QTextEdit, QVBoxLayout, QHBoxLayout,
    QTreeWidget, QTreeWidgetItem, QTableWidget,
    QTableWidgetItem, QMessageBox, QProgressBar
)
from PyQt6.QtGui import QColor
from PyQt6.QtCore import Qt, QThread, pyqtSignal


# Worker Thread

class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, input_path, output_path):
        super().__init__()
        self.input_path = input_path
        self.output_path = output_path

    def run(self):
        self.log_signal.emit("[*] Starting  Deep Inspector...\n")

        process = subprocess.Popen(
            ["python", "backend.py"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )

        process.stdin.write(self.input_path + "\n")
        process.stdin.write(self.output_path + "\n")
        process.stdin.flush()

        for line in process.stdout:
            self.log_signal.emit(line)

        process.wait()
        self.log_signal.emit("\n[OK] Scan completed\n")
        self.finished_signal.emit()



# Main UI

class PolyADSUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Deep Inspector – Anti-Forensic Detection")
        self.resize(1100, 750)

        self.input_path = ""
        self.output_path = ""

        self.init_ui()
        self.apply_theme()

    def init_ui(self):
        layout = QVBoxLayout()

        # ---- Input selection ----
        input_layout = QHBoxLayout()
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Select file or folder")
        input_layout.addWidget(self.input_edit)

        btn_file = QPushButton("📄 File")
        btn_file.clicked.connect(self.select_file)
        input_layout.addWidget(btn_file)

        btn_folder = QPushButton("📁 Folder")
        btn_folder.clicked.connect(self.select_folder)
        input_layout.addWidget(btn_folder)

        layout.addLayout(input_layout)

        # ---- Output selection ----
        output_layout = QHBoxLayout()
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText("Select output directory")
        output_layout.addWidget(self.output_edit)

        btn_out = QPushButton("📁 Output")
        btn_out.clicked.connect(self.select_output)
        output_layout.addWidget(btn_out)

        layout.addLayout(output_layout)

        # ---- Progress Bar ----
        self.progress = QProgressBar()
        self.progress.setTextVisible(True)
        self.progress.setFormat("Scanning...")
        self.progress.setRange(0, 1)
        layout.addWidget(self.progress)

        # ---- Scan button ----
        self.scan_btn = QPushButton("🚀 Scan")
        self.scan_btn.clicked.connect(self.start_scan)
        layout.addWidget(self.scan_btn)

        # ---- Log box ----
        self.log_box = QTextEdit()
        self.log_box.setReadOnly(True)
        layout.addWidget(QLabel("Scan Log"))
        layout.addWidget(self.log_box)

        # ---- Results table ----
        layout.addWidget(QLabel("Results"))
        self.table = QTableWidget()
        layout.addWidget(self.table)

        # ---- Tree view ----
        layout.addWidget(QLabel("File → ADS Streams"))
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["Item", "Risk Likelihood", "Indicators"])
        layout.addWidget(self.tree)

        # ---- Open output ----
        btn_open = QPushButton("📂 Open Output Folder")
        btn_open.clicked.connect(self.open_output)
        layout.addWidget(btn_open)

        self.setLayout(layout)

    
    # Blue Theme

    def apply_theme(self):
        self.setStyleSheet("""
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
        QPushButton:hover {
            background-color: #3a66f0;
        }
        QPushButton:pressed {
            background-color: #163bb3;
        }

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
        QProgressBar::chunk {
            background-color: #1f77ff;
        }

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
        """)

    
    # Dialogs

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

    
    # Scan Logic

    def start_scan(self):
        self.input_path = self.input_edit.text().strip()
        self.output_path = self.output_edit.text().strip()

        if not self.input_path or not self.output_path:
            QMessageBox.warning(self, "Missing Input", "Select input and output paths.")
            return

        os.makedirs(self.output_path, exist_ok=True)
        self.log_box.clear()
        self.tree.clear()
        self.table.clear()

        self.progress.setRange(0, 0)  # indeterminate

        self.worker = ScanWorker(self.input_path, self.output_path)
        self.worker.log_signal.connect(self.log_box.insertPlainText)
        self.worker.finished_signal.connect(self.load_results)
        self.worker.start()

    
    # Load CSV

    def load_results(self):
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

    def open_output(self):
        if self.output_path:
            os.startfile(self.output_path)



# Run App

if __name__ == "__main__":
    app = QApplication(sys.argv)
    win = PolyADSUI()
    win.show()
    sys.exit(app.exec())
