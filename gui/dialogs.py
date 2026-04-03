"""Dialog windows for the VirusProbe GUI."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from PySide6.QtCore import QRegularExpression, QTimer, Qt
from PySide6.QtGui import QRegularExpressionValidator
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSizePolicy,
    QSpinBox,
    QVBoxLayout,
    QWidget,
)

from common import (
    THEME_AUTO,
    THEME_DARK,
    THEME_LIGHT,
    UPLOAD_AUTO,
    UPLOAD_MANUAL,
    UPLOAD_NEVER,
    is_valid_hash,
)
from .workflows import ReportRequest


class AddHashesDialog(QDialog):
    _AUTO_CLOSE_DELAY = 500

    def __init__(self, parent: QWidget, add_item: Callable[[str, str], bool]) -> None:
        super().__init__(parent)
        self.setWindowTitle("Add Hashes")
        self.setMinimumSize(560, 360)
        self.setSizeGripEnabled(True)
        self._add_item = add_item
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        title = QLabel("Enter one or more hashes (MD5, SHA-1, or SHA-256).")
        font = title.font()
        font.setBold(True)
        font.setPointSize(font.pointSize() + 1)
        title.setFont(font)
        layout.addWidget(title)

        layout.addWidget(QLabel("Enter one hash per line. A single hash is supported too."))
        self._text = QPlainTextEdit()
        layout.addWidget(self._text)
        layout.addWidget(QLabel("Example: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"))

        self._status_lbl = QLabel("")
        layout.addWidget(self._status_lbl)

        btn_box = QDialogButtonBox()
        add_btn = btn_box.addButton("Add", QDialogButtonBox.ButtonRole.AcceptRole)
        add_btn.setObjectName("primaryButton")
        btn_box.addButton(QDialogButtonBox.StandardButton.Cancel)
        add_btn.clicked.connect(self._add_hashes)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _add_hashes(self) -> None:
        raw = self._text.toPlainText().strip()
        if not raw:
            self._status_lbl.setText("No hashes provided.")
            return

        tokens = [line.strip() for line in raw.splitlines() if line.strip()]
        added = 0
        invalid: list[str] = []
        duplicates = 0
        seen: set[str] = set()

        for token in tokens:
            value = token.lower()
            if value in seen:
                duplicates += 1
                continue
            seen.add(value)
            if not is_valid_hash(value):
                invalid.append(token)
                continue
            if self._add_item("hash", value):
                added += 1
            else:
                duplicates += 1

        parts = [f"Added {added} hash{'es' if added != 1 else ''}."]
        if invalid:
            parts.append(f"Skipped {len(invalid)} invalid.")
        if duplicates:
            parts.append(f"Ignored {duplicates} duplicate{'s' if duplicates != 1 else ''}.")
        self._status_lbl.setText(" ".join(parts))
        if added > 0:
            QTimer.singleShot(self._AUTO_CLOSE_DELAY, self.accept)


class ReportSavedDialog(QDialog):
    def __init__(
        self,
        parent: QWidget,
        output_path: str,
        open_path: Callable[[str], None],
        open_folder: Callable[[str], None],
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Report Saved")
        self.setMinimumWidth(400)
        self._output_path = output_path
        self._open_path = open_path
        self._open_folder = open_folder
        self._build()

    def _build(self) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(8)

        layout.addWidget(QLabel("Report saved successfully."))
        path_lbl = QLabel(self._output_path)
        path_lbl.setWordWrap(True)
        path_lbl.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        layout.addWidget(path_lbl)

        btn_box = QDialogButtonBox()
        open_report_btn = btn_box.addButton("Open Report", QDialogButtonBox.ButtonRole.ActionRole)
        open_report_btn.setObjectName("successButton")
        open_folder_btn = btn_box.addButton("Open Folder", QDialogButtonBox.ButtonRole.ActionRole)
        btn_box.addButton(QDialogButtonBox.StandardButton.Close)
        open_report_btn.clicked.connect(self._on_open_report)
        open_folder_btn.clicked.connect(self._on_open_folder)
        btn_box.rejected.connect(self.accept)
        layout.addWidget(btn_box)

    def _on_open_report(self) -> None:
        self._open_path(self._output_path)
        self.accept()

    def _on_open_folder(self) -> None:
        self._open_folder(self._output_path)
        self.accept()


class GenerateReportDialog(QDialog):
    def __init__(self, parent: QWidget, default_dir: str) -> None:
        super().__init__(parent)
        self.setWindowTitle("Generate Report")
        self.setMinimumWidth(440)
        self._result: ReportRequest | None = None
        default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._build(default_name, default_dir)

    def _build(self, default_name: str, default_dir: str) -> None:
        layout = QVBoxLayout(self)
        form = QFormLayout()
        form.setSpacing(8)

        self._name_edit = QLineEdit(default_name)
        self._name_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[^/\\\\:*?\"<>|]+"), self))
        form.addRow("Report Name:", self._name_edit)

        self._fmt_combo = QComboBox()
        self._fmt_combo.addItems(["json", "csv", "txt", "md"])
        form.addRow("Format:", self._fmt_combo)

        row = QHBoxLayout()
        self._dir_edit = QLineEdit(default_dir)
        row.addWidget(self._dir_edit)
        browse_btn = QPushButton("Browse...")
        browse_btn.clicked.connect(self._browse_folder)
        row.addWidget(browse_btn)
        form.addRow("Folder:", row)
        layout.addLayout(form)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        create_btn = btn_box.button(QDialogButtonBox.StandardButton.Ok)
        create_btn.setText("Create")
        create_btn.setObjectName("primaryButton")
        btn_box.accepted.connect(self._confirm)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    def _browse_folder(self) -> None:
        chosen = QFileDialog.getExistingDirectory(self, "Select report folder", self._dir_edit.text())
        if chosen:
            self._dir_edit.setText(chosen)

    def _confirm(self) -> None:
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Invalid Name", "Enter a report name.")
            return

        folder_path = Path(self._dir_edit.text().strip() or Path.home())
        folder_path.mkdir(parents=True, exist_ok=True)
        fmt = self._fmt_combo.currentText().strip().lower()
        output_path = str(folder_path / f"{name}.{fmt}")
        self._result = ReportRequest(new_dir=str(folder_path), output_path=output_path, report_format=fmt)
        self.accept()


class AdvancedDialog(QDialog):
    _MAX_WORKERS = 50
    _MAX_RPM = 500
    _MAX_UPLOAD_TIMEOUT = 7200
    _THEME_VALUES = (THEME_AUTO, THEME_DARK, THEME_LIGHT)
    _LABEL_WIDTH = 150
    _FIELD_WIDTH = 220

    def __init__(
        self,
        parent: QWidget,
        current_rpm: int,
        current_workers: int,
        current_upload_timeout: int,
        current_upload_mode: str,
        current_theme_mode: str,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Advanced Scan Settings")
        self.setMinimumWidth(380)
        self.setFixedWidth(460)
        self.setSizeGripEnabled(False)
        self._result: tuple[int, int, int, str, str] | None = None
        self._build(current_rpm, current_workers, current_upload_timeout, current_upload_mode, current_theme_mode)

    def _build(
        self,
        current_rpm: int,
        current_workers: int,
        current_upload_timeout: int,
        current_upload_mode: str,
        current_theme_mode: str,
    ) -> None:
        layout = QVBoxLayout(self)
        layout.setSpacing(10)

        layout.addWidget(self._section_label("Appearance"))
        theme_form = QFormLayout()
        theme_form.setSpacing(6)
        theme_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        theme_form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        theme_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
        self._theme_combo = QComboBox()
        self._theme_combo.addItems([value.title() for value in self._THEME_VALUES])
        self._theme_combo.setCurrentText(
            current_theme_mode.title() if current_theme_mode in self._THEME_VALUES else THEME_AUTO.title()
        )
        self._theme_combo.setFixedWidth(self._FIELD_WIDTH)
        theme_form.addRow(self._field_label("Theme:"), self._theme_combo)
        layout.addLayout(theme_form)

        layout.addWidget(self._section_label("Scan Performance"))
        form = QFormLayout()
        form.setSpacing(6)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)
        self._workers_spin = QSpinBox()
        self._workers_spin.setRange(1, self._MAX_WORKERS)
        self._workers_spin.setValue(current_workers)
        self._workers_spin.setFixedWidth(self._FIELD_WIDTH)
        form.addRow(self._field_label("Workers:"), self._workers_spin)

        self._rpm_spin = QSpinBox()
        self._rpm_spin.setRange(0, self._MAX_RPM)
        self._rpm_spin.setValue(current_rpm)
        self._rpm_spin.setSpecialValueText("Unlimited")
        self._rpm_spin.setFixedWidth(self._FIELD_WIDTH)
        form.addRow(self._field_label("Requests per minute:"), self._rpm_spin)
        layout.addLayout(form)

        layout.addWidget(self._section_label("Upload Behavior"))
        upload_form = QFormLayout()
        upload_form.setSpacing(6)
        upload_form.setLabelAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)
        upload_form.setFormAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        upload_form.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.FieldsStayAtSizeHint)

        self._upload_mode_combo = QComboBox()
        self._upload_mode_combo.addItem("Never upload", UPLOAD_NEVER)
        self._upload_mode_combo.addItem("Manual upload", UPLOAD_MANUAL)
        self._upload_mode_combo.addItem("Auto-upload undetected files", UPLOAD_AUTO)
        current_upload_index = max(0, self._upload_mode_combo.findData(current_upload_mode))
        self._upload_mode_combo.setCurrentIndex(current_upload_index)
        self._upload_mode_combo.setFixedWidth(self._FIELD_WIDTH)
        upload_form.addRow(self._field_label("Mode:"), self._upload_mode_combo)

        self._timeout_spin = QSpinBox()
        self._timeout_spin.setRange(0, self._MAX_UPLOAD_TIMEOUT)
        self._timeout_spin.setValue(current_upload_timeout)
        self._timeout_spin.setSpecialValueText("None")
        self._timeout_spin.setFixedWidth(self._FIELD_WIDTH)
        self._timeout_label = self._field_label("Upload timeout:")
        upload_form.addRow(self._timeout_label, self._timeout_spin)
        hint = QLabel("Only used when uploads are allowed.")
        hint.setObjectName("subtleText")
        hint.setContentsMargins(2, 0, 0, 0)
        upload_form.addRow(self._field_label(""), hint)
        layout.addLayout(upload_form)

        self._upload_mode_combo.currentIndexChanged.connect(lambda _index: self._sync_upload_controls())
        self._sync_upload_controls()

        layout.addSpacing(4)

        btn_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Apply | QDialogButtonBox.StandardButton.Cancel
        )
        apply_btn = btn_box.button(QDialogButtonBox.StandardButton.Apply)
        apply_btn.setObjectName("primaryButton")
        apply_btn.clicked.connect(self._apply)
        btn_box.rejected.connect(self.reject)
        layout.addWidget(btn_box)

    @staticmethod
    def _section_label(text: str) -> QLabel:
        label = QLabel(text)
        font = label.font()
        font.setBold(True)
        label.setFont(font)
        label.setObjectName("sectionLabel")
        label.setContentsMargins(0, 8, 0, 2)
        return label

    @classmethod
    def _field_label(cls, text: str) -> QLabel:
        label = QLabel(text)
        label.setFixedWidth(cls._LABEL_WIDTH)
        return label

    def _sync_upload_controls(self) -> None:
        enabled = self._upload_mode_combo.currentData() != UPLOAD_NEVER
        self._timeout_label.setEnabled(enabled)
        self._timeout_spin.setEnabled(enabled)

    def _apply(self) -> None:
        mode = str(self._upload_mode_combo.currentData())
        self._result = (
            max(0, self._rpm_spin.value()),
            max(1, self._workers_spin.value()),
            max(0, self._timeout_spin.value()),
            mode,
            self._theme_combo.currentText().lower(),
        )
        self.accept()


def show_set_api_key_dialog(parent: QWidget, current_key: str | None) -> str | None:
    dialog = QInputDialog(parent)
    dialog.setWindowTitle("VirusTotal API Key")
    dialog.setLabelText("Enter API key:")
    dialog.setTextEchoMode(QLineEdit.EchoMode.Password)
    dialog.setTextValue(current_key or "")
    dialog.setMinimumWidth(380)
    line_edit = dialog.findChild(QLineEdit)
    if line_edit is not None:
        line_edit.setValidator(QRegularExpressionValidator(QRegularExpression(r"[0-9A-Fa-f]{0,64}"), dialog))
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return None
    return dialog.textValue().strip()


def show_add_hashes_dialog(parent: QWidget, add_item: Callable[[str, str], bool]) -> None:
    AddHashesDialog(parent, add_item).exec()


def show_generate_report_dialog(parent: QWidget, default_dir: str) -> ReportRequest | None:
    dialog = GenerateReportDialog(parent, default_dir)
    dialog.exec()
    return dialog._result


def show_report_saved_dialog(
    parent: QWidget,
    output_path: str,
    open_path: Callable[[str], None],
    open_folder: Callable[[str], None],
) -> None:
    ReportSavedDialog(parent, output_path, open_path, open_folder).exec()


def show_advanced_dialog(
    parent: QWidget,
    current_rpm: int,
    current_workers: int,
    current_upload_timeout: int,
    current_upload_mode: str = "never",
    current_theme_mode: str = "auto",
) -> tuple[int, int, int, str, str] | None:
    dialog = AdvancedDialog(
        parent,
        current_rpm,
        current_workers,
        current_upload_timeout,
        current_upload_mode,
        current_theme_mode,
    )
    dialog.exec()
    return dialog._result
