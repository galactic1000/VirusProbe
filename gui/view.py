"""Designer-loaded Qt view layer for VirusProbe GUI."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QFile, QModelIndex, QPersistentModelIndex, QRect, Qt, Signal, Slot
from PySide6.QtGui import QAction, QColor, QDragEnterEvent, QDragMoveEvent, QDropEvent, QKeySequence, QPaintEvent, QPainter, QPalette
from PySide6.QtUiTools import QUiLoader
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMenu,
    QProgressBar,
    QPushButton,
    QStyledItemDelegate,
    QStyleOptionViewItem,
    QTableView,
    QToolButton,
    QWidget,
)

from .results_model import ResultsFilterProxyModel, ResultsTableModel, UiState
from .workflows import PendingScanEntry


def _refresh_style(widget: QWidget) -> None:
    style = widget.style()
    if style is None:
        return
    style.unpolish(widget)
    style.polish(widget)
    widget.update()


class StatusDelegate(QStyledItemDelegate):
    """Color-codes the Status column text based on the status value."""

    _DARK: dict[str, QColor] = {
        "good":      QColor("#4ade80"),
        "malicious": QColor("#f87171"),
        "suspicious":QColor("#fb923c"),
        "error":     QColor("#f87171"),
        "muted":     QColor("#94a3b8"),
        "active":    QColor("#60a5fa"),
    }
    _LIGHT: dict[str, QColor] = {
        "good":      QColor("#15803d"),
        "malicious": QColor("#dc2626"),
        "suspicious":QColor("#d97706"),
        "error":     QColor("#dc2626"),
        "muted":     QColor("#64748b"),
        "active":    QColor("#2563eb"),
    }

    def _color_for(self, status: str) -> QColor | None:
        s = status.lower()
        app = QApplication.instance()
        is_dark = app is not None and app.styleHints().colorScheme() == Qt.ColorScheme.Dark  # type: ignore
        palette = self._DARK if is_dark else self._LIGHT
        if "malicious" in s:
            return palette["malicious"]
        if "suspicious" in s:
            return palette["suspicious"]
        if "error" in s:
            return palette["error"]
        if "undetected" in s or "clean" in s or "uploaded" in s:
            return palette["good"]
        if "cancelled" in s or s == "pending":
            return palette["muted"]
        if "scanning" in s or "uploading" in s:
            return palette["active"]
        return None

    def initStyleOption(self, option: QStyleOptionViewItem, index: QModelIndex | QPersistentModelIndex) -> None:
        super().initStyleOption(option, index)
        color = self._color_for(index.data() or "")
        if color is not None:
            option.palette.setColor(QPalette.ColorGroup.Active, QPalette.ColorRole.Text, color)
            option.palette.setColor(QPalette.ColorGroup.Inactive, QPalette.ColorRole.Text, color)


class DropTableView(QTableView):
    """Table view that paints an empty-state overlay and accepts dropped files."""

    drop_received = Signal(list)
    _TYPE_WIDTH = 90
    _VALUE_WIDTH = 550
    _STATUS_WIDTH = 160

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.DropOnly)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.setSortingEnabled(True)
        self.setAlternatingRowColors(False)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.verticalHeader().setVisible(False)

    def paintEvent(self, event: QPaintEvent) -> None:
        super().paintEvent(event)
        model = self.model()
        if model is not None and model.rowCount() > 0:
            return

        painter = QPainter(self.viewport())
        painter.save()
        rect = self.viewport().rect()
        mid_y = rect.height() // 2

        text_color = self.palette().color(QPalette.ColorRole.PlaceholderText)
        if not text_color.isValid() or text_color == QColor(0, 0, 0, 0):
            text_color = self.palette().color(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text)

        painter.setPen(text_color)
        title_font = self.font()
        title_font.setPointSize(17)
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(QRect(rect.x(), mid_y - 36, rect.width(), 32), Qt.AlignmentFlag.AlignCenter, "Drop Files Here")

        hint_font = self.font()
        hint_font.setPointSize(10)
        painter.setFont(hint_font)
        painter.drawText(QRect(rect.x(), mid_y + 2, rect.width(), 22), Qt.AlignmentFlag.AlignCenter, "or use Add Item")
        painter.restore()

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event: QDragMoveEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event: QDropEvent) -> None:
        if event.mimeData().hasUrls():
            paths = [url.toLocalFile() for url in event.mimeData().urls()]
            self.drop_received.emit(paths)
            event.acceptProposedAction()
            return
        event.ignore()


class MainWindow:
    """Loads the main window UI and exposes a Qt-native view API."""

    def __init__(
        self,
        root: QMainWindow,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_add_files: Callable[[], None],
        on_add_hashes: Callable[[], None],
        on_remove_selected: Callable[[], None],
        on_clear_items: Callable[[], None],
        on_advanced: Callable[[], None],
        on_scan: Callable[[], None],
        on_upload: Callable[[], None],
        on_drop_files: Callable[[list[str]], None],
        on_generate_report: Callable[[], None],
        on_copy_value: Callable[[str], None],
    ) -> None:
        self.root = root
        self._iid_counter = itertools.count(1)
        self._progress_text = "Ready"

        self.central_widget = self._load_ui()
        self._bind_widgets()
        self._build_table(on_drop_files)
        self._build_actions(
            on_clear_cache=on_clear_cache,
            on_set_api_key=on_set_api_key,
            on_add_files=on_add_files,
            on_add_hashes=on_add_hashes,
            on_remove_selected=on_remove_selected,
            on_clear_items=on_clear_items,
            on_advanced=on_advanced,
            on_scan=on_scan,
            on_upload=on_upload,
            on_generate_report=on_generate_report,
            on_copy_value=on_copy_value,
        )
        self._wire_buttons(
            on_clear_cache=on_clear_cache,
            on_set_api_key=on_set_api_key,
            on_remove_selected=on_remove_selected,
            on_clear_items=on_clear_items,
            on_advanced=on_advanced,
            on_scan=on_scan,
            on_upload=on_upload,
            on_generate_report=on_generate_report,
        )

    def _load_ui(self) -> QWidget:
        ui_path = Path(__file__).resolve().parent / "assets" / "main_window.ui"
        loader = QUiLoader()
        loader.registerCustomWidget(DropTableView)
        ui_file = QFile(str(ui_path))
        if not ui_file.open(QFile.OpenModeFlag.ReadOnly):
            raise RuntimeError(f"Unable to open UI file: {ui_path}")
        try:
            widget = loader.load(ui_file, self.root)
        finally:
            ui_file.close()
        if widget is None:
            raise RuntimeError(f"Unable to load UI file: {ui_path}")
        return widget

    def _bind_widgets(self) -> None:
        self.top_bar = self._require(QWidget, "topBar")
        self.toolbar = self._require(QWidget, "toolbar")
        self.content_pane = self._require(QWidget, "contentPane")
        self.status_bar = self._require(QWidget, "statusBar")
        self.app_title = self._require(QLabel, "appTitle")
        self._api_status_lbl = self._require(QLabel, "apiStatusLabel")
        self._upload_indicator_lbl = self._require(QLabel, "uploadIndicatorLabel")
        self._progress_lbl = self._require(QLabel, "progressLabel")
        self._search_edit = self._require(QLineEdit, "searchEdit")
        self.table = self._require(DropTableView, "resultsTable")
        self.set_api_key_btn = self._require(QPushButton, "setApiKeyButton")
        self.clear_cache_btn = self._require(QPushButton, "clearCacheButton")
        self.advanced_btn = self._require(QPushButton, "advancedButton")
        self.add_menu_btn = self._require(QToolButton, "addItemButton")
        self.remove_btn = self._require(QPushButton, "removeSelectedButton")
        self.clear_btn = self._require(QPushButton, "clearListButton")
        self.upload_action_btn = self._require(QPushButton, "uploadButton")
        self.scan_btn = self._require(QPushButton, "scanButton")
        self.report_btn = self._require(QPushButton, "reportButton")
        self.progress_bar = self._require(QProgressBar, "progressBar")

        title_font = self.app_title.font()
        title_font.setPointSize(16)
        title_font.setBold(True)
        self.app_title.setFont(title_font)
        self._api_status_lbl.setObjectName("subtleText")
        self._upload_indicator_lbl.setObjectName("accentText")
        self._progress_lbl.setObjectName("statusText")
        self.clear_cache_btn.setObjectName("dangerButton")
        self.upload_action_btn.setObjectName("accentButton")
        self.scan_btn.setObjectName("primaryButton")
        self.report_btn.setObjectName("successButton")
        self.scan_btn.setMinimumWidth(70)
        self.progress_bar.setVisible(False)
        self.report_btn.setEnabled(False)
        self.upload_action_btn.setVisible(False)

    def _build_table(self, on_drop_files: Callable[[list[str]], None]) -> None:
        self.results_model = ResultsTableModel(self.central_widget)
        self.proxy_model = ResultsFilterProxyModel(self.central_widget)
        self.proxy_model.setSourceModel(self.results_model)

        self.table.setModel(self.proxy_model)
        self.table.drop_received.connect(on_drop_files)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.table.setColumnWidth(0, self.table._TYPE_WIDTH)
        self.table.setColumnWidth(2, self.table._STATUS_WIDTH)
        self.table.setItemDelegateForColumn(2, StatusDelegate(self.table))

        self._search_edit.textChanged.connect(self.proxy_model.set_search_text)

    def _build_actions(
        self,
        *,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_add_files: Callable[[], None],
        on_add_hashes: Callable[[], None],
        on_remove_selected: Callable[[], None],
        on_clear_items: Callable[[], None],
        on_advanced: Callable[[], None],
        on_scan: Callable[[], None],
        on_upload: Callable[[], None],
        on_generate_report: Callable[[], None],
        on_copy_value: Callable[[str], None],
    ) -> None:
        self.set_api_key_action = QAction("Set API Key", self.root)
        self.set_api_key_action.triggered.connect(on_set_api_key)

        self.clear_cache_action = QAction("Clear Cache", self.root)
        self.clear_cache_action.triggered.connect(on_clear_cache)

        self.advanced_action = QAction("Advanced...", self.root)
        self.advanced_action.triggered.connect(on_advanced)

        self.add_files_action = QAction("Add File(s)...", self.root)
        self.add_files_action.triggered.connect(on_add_files)

        self.add_hashes_action = QAction("Add Hash(es)...", self.root)
        self.add_hashes_action.triggered.connect(on_add_hashes)

        self.remove_selected_action = QAction("Remove Selected", self.table)
        self.remove_selected_action.setShortcut(QKeySequence.StandardKey.Delete)
        self.remove_selected_action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.remove_selected_action.triggered.connect(on_remove_selected)
        self.table.addAction(self.remove_selected_action)

        self.copy_value_action = QAction("Copy Value", self.table)
        self.copy_value_action.setShortcut(QKeySequence.StandardKey.Copy)
        self.copy_value_action.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        self.copy_value_action.triggered.connect(lambda: self.copy_selected_value(on_copy_value))
        self.table.addAction(self.copy_value_action)

        self.clear_items_action = QAction("Clear List", self.root)
        self.clear_items_action.setShortcut(QKeySequence("Ctrl+L"))
        self.clear_items_action.triggered.connect(on_clear_items)
        self.root.addAction(self.clear_items_action)

        self.scan_action = QAction("Scan", self.root)
        self.scan_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        self.scan_action.triggered.connect(on_scan)
        self.root.addAction(self.scan_action)

        self.upload_action = QAction("Upload", self.root)
        self.upload_action.setShortcut(QKeySequence("Ctrl+Shift+U"))
        self.upload_action.triggered.connect(on_upload)
        self.root.addAction(self.upload_action)

        self.report_action = QAction("Generate Report", self.root)
        self.report_action.setShortcut(QKeySequence("Ctrl+Shift+R"))
        self.report_action.triggered.connect(on_generate_report)
        self.root.addAction(self.report_action)

        add_menu = QMenu(self.add_menu_btn)
        add_menu.addAction(self.add_files_action)
        add_menu.addAction(self.add_hashes_action)
        self.add_menu_btn.setMenu(add_menu)

    def _wire_buttons(
        self,
        *,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_remove_selected: Callable[[], None],
        on_clear_items: Callable[[], None],
        on_advanced: Callable[[], None],
        on_scan: Callable[[], None],
        on_upload: Callable[[], None],
        on_generate_report: Callable[[], None],
    ) -> None:
        del on_clear_cache, on_set_api_key, on_remove_selected, on_clear_items, on_advanced, on_scan, on_upload, on_generate_report
        self.set_api_key_btn.clicked.connect(self.set_api_key_action.trigger)
        self.clear_cache_btn.clicked.connect(self.clear_cache_action.trigger)
        self.advanced_btn.clicked.connect(self.advanced_action.trigger)
        self.remove_btn.clicked.connect(self.remove_selected_action.trigger)
        self.clear_btn.clicked.connect(self.clear_items_action.trigger)
        self.scan_btn.clicked.connect(self.scan_action.trigger)
        self.upload_action_btn.clicked.connect(self.upload_action.trigger)
        self.report_btn.clicked.connect(self.report_action.trigger)

    def bind_state(self, state: UiState) -> None:
        state.api_status_changed.connect(self.set_api_status_text)
        state.upload_indicator_changed.connect(self.set_upload_indicator_text)
        state.progress_text_changed.connect(self.set_progress_text)
        state.controls_enabled_changed.connect(self.set_controls_enabled)
        state.scan_button_enabled_changed.connect(self.set_scan_button_enabled)
        state.report_button_enabled_changed.connect(self.set_report_button_enabled)
        state.upload_button_visible_changed.connect(self.show_upload_button)
        state.upload_button_enabled_changed.connect(self.set_upload_button_enabled)
        state.progress_changed.connect(self.set_progress)

    def _require[T: QWidget](self, expected_type: type[T], name: str) -> T:
        widget = self.central_widget.findChild(expected_type, name)
        if widget is None:
            raise RuntimeError(f"Missing UI widget: {name}")
        return widget

    @Slot(str)
    def set_api_status_text(self, text: str) -> None:
        self._api_status_lbl.setText(text)

    @Slot(str)
    def set_upload_indicator_text(self, text: str) -> None:
        self._upload_indicator_lbl.setText(text)

    @Slot(str)
    def set_progress_text(self, text: str) -> None:
        self._progress_text = text
        self._progress_lbl.setText(text)

    def get_progress_text(self) -> str:
        return self._progress_text

    @Slot(bool)
    def set_scan_button_enabled(self, enabled: bool) -> None:
        self.scan_action.setEnabled(enabled)
        self.scan_btn.setEnabled(enabled)

    def _disconnect_scan_button(self) -> None:
        try:
            self.scan_action.triggered.disconnect()
        except RuntimeError:
            pass

    def set_scan_button_scan(self, on_scan: Callable[[], None]) -> None:
        self.scan_btn.setObjectName("primaryButton")
        self.scan_btn.setText("Scan")
        self.scan_action.setText("Scan")
        self.scan_action.setEnabled(True)
        self._disconnect_scan_button()
        self.scan_action.triggered.connect(on_scan)
        self.scan_btn.setEnabled(True)
        _refresh_style(self.scan_btn)

    def set_scan_button_cancel(self, on_cancel: Callable[[], None]) -> None:
        self.scan_btn.setObjectName("dangerButton")
        self.scan_btn.setText("Cancel")
        self.scan_action.setText("Cancel")
        self.scan_action.setEnabled(True)
        self._disconnect_scan_button()
        self.scan_action.triggered.connect(on_cancel)
        self.scan_btn.setEnabled(True)
        _refresh_style(self.scan_btn)

    @Slot(bool)
    def set_report_button_enabled(self, enabled: bool) -> None:
        self.report_action.setEnabled(enabled)
        self.report_btn.setEnabled(enabled)

    @Slot(bool)
    def set_controls_enabled(self, enabled: bool) -> None:
        self.set_api_key_action.setEnabled(enabled)
        self.clear_cache_action.setEnabled(enabled)
        self.advanced_action.setEnabled(enabled)
        self.remove_selected_action.setEnabled(enabled)
        self.clear_items_action.setEnabled(enabled)
        self.add_menu_btn.setEnabled(enabled)
        self.remove_btn.setEnabled(enabled)
        self.clear_btn.setEnabled(enabled)
        self.set_api_key_btn.setEnabled(enabled)
        self.clear_cache_btn.setEnabled(enabled)
        self.advanced_btn.setEnabled(enabled)

    @Slot(bool)
    def show_upload_button(self, visible: bool) -> None:
        self.upload_action_btn.setVisible(visible)

    @Slot(bool)
    def set_upload_button_enabled(self, enabled: bool) -> None:
        self.upload_action.setEnabled(enabled)
        self.upload_action_btn.setEnabled(enabled)

    @Slot(int, int)
    def set_progress(self, completed: int, total: int) -> None:
        if total <= 0:
            self.progress_bar.setVisible(False)
            self.progress_bar.setMaximum(1)
            self.progress_bar.setValue(0)
            self.progress_bar.setFormat("")
            return
        self.progress_bar.setVisible(True)
        self.progress_bar.setMaximum(total)
        clamped = min(completed, total)
        self.progress_bar.setValue(clamped)
        self.progress_bar.setFormat(f"{clamped}/{total}")

    def has_selection(self) -> bool:
        selection_model = self.table.selectionModel()
        return selection_model is not None and selection_model.hasSelection()

    @property
    def separator_width(self) -> int:
        return max(72, self.root.width())

    def add_item(self, item_type: str, value: str) -> bool:
        return self.results_model.add_item(item_type, value, f"I{next(self._iid_counter)}")

    def _selected_iids(self) -> list[str]:
        iids: list[str] = []
        for index in self._selected_source_rows():
            if iid := self.results_model.get_iid_for_row(index.row()):
                iids.append(iid)
        return iids

    def _selected_source_rows(self, *, preferred_column: int = 0) -> list[QModelIndex]:
        selection_model = self.table.selectionModel()
        if selection_model is None:
            return []
        proxy_rows = selection_model.selectedRows(preferred_column)
        if not proxy_rows:
            current_index = selection_model.currentIndex()
            if current_index.isValid():
                proxy_rows = [self.proxy_model.index(current_index.row(), preferred_column)]
        return [self.proxy_model.mapToSource(proxy_index) for proxy_index in proxy_rows if proxy_index.isValid()]

    def remove_selected(self) -> list[tuple[str, str]]:
        return self.results_model.remove_rows_by_iids(self._selected_iids())

    def copy_selected_value(self, on_copy_value: Callable[[str], None]) -> None:
        source_rows = self._selected_source_rows(preferred_column=1)
        if not source_rows:
            return
        source_index = source_rows[0]
        value = self.results_model.data(self.results_model.index(source_index.row(), 1))
        if value is not None:
            on_copy_value(str(value))

    def clear_items(self) -> None:
        self.results_model.clear()

    def item_count(self) -> int:
        return self.results_model.item_count()

    def collect_pending_entries(self) -> list[PendingScanEntry]:
        return self.results_model.collect_pending_entries()

    def result_keys_in_order(self) -> list[tuple[str, str]]:
        return self.results_model.result_keys_in_order()

    def set_row_status(self, iid: str, status: str) -> None:
        self.results_model.set_row_status(iid, status)

    def mark_rows_status_if_current(self, iids: list[str], from_status: str, to_status: str) -> None:
        self.results_model.mark_rows_status_if_current(iids, from_status, to_status)

    def has_uploadable_undetected(self) -> bool:
        return self.results_model.has_uploadable_undetected()

    def undetected_files(self, selected_only: bool = False) -> list[tuple[str, str]]:
        iids = self._selected_iids() if selected_only else None
        return self.results_model.undetected_files(iids)
