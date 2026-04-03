"""Qt model/view classes for queued scan items and results."""

from __future__ import annotations

from dataclasses import dataclass

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QObject, QPersistentModelIndex, QSortFilterProxyModel, Qt, Signal, Slot

from common import ScanTargetKind
from .workflows import PendingScanEntry


@dataclass
class ResultRow:
    iid: str
    item_type: str
    value: str
    status: str = "Pending"


class ResultsTableModel(QAbstractTableModel):
    headers = ("Type", "Value", "Status")

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._rows: list[ResultRow] = []
        self._keys: set[tuple[str, str]] = set()
        self._iid_to_row: dict[str, int] = {}

    def rowCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self.headers)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole) -> str | None:
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal and 0 <= section < len(self.headers):
            return self.headers[section]
        return None

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> str | None:
        if not index.isValid():
            return None
        row = self._rows[index.row()]
        if role in (Qt.ItemDataRole.DisplayRole, Qt.ItemDataRole.EditRole):
            return (row.item_type, row.value, row.status)[index.column()]
        if role == Qt.ItemDataRole.UserRole:
            return row.iid
        return None

    @staticmethod
    def _normalize_value(item_type: str, value: str) -> str:
        if item_type == ScanTargetKind.HASH:
            return value.strip().lower()
        return value

    @classmethod
    def _item_key(cls, item_type: str, value: str) -> tuple[str, str]:
        return item_type, cls._normalize_value(item_type, value)

    def add_item(self, item_type: str, value: str, iid: str) -> bool:
        normalized = self._normalize_value(item_type, value)
        key = (item_type, normalized)
        if key in self._keys:
            return False
        row_idx = len(self._rows)
        self.beginInsertRows(QModelIndex(), row_idx, row_idx)
        self._rows.append(ResultRow(iid=iid, item_type=item_type, value=normalized))
        self.endInsertRows()
        self._keys.add(key)
        self._iid_to_row[iid] = row_idx
        return True

    def remove_rows_by_iids(self, iids: list[str]) -> list[tuple[str, str]]:
        removed: list[tuple[str, str]] = []
        row_indexes = sorted(
            {self._iid_to_row[iid] for iid in iids if iid in self._iid_to_row},
            reverse=True,
        )
        for row_idx in row_indexes:
            row = self._rows[row_idx]
            self.beginRemoveRows(QModelIndex(), row_idx, row_idx)
            self._rows.pop(row_idx)
            self.endRemoveRows()
            self._keys.discard((row.item_type, row.value))
            removed.append((row.item_type, row.value))
        self._reindex()
        removed.reverse()
        return removed

    def clear(self) -> None:
        if not self._rows:
            return
        self.beginResetModel()
        self._rows.clear()
        self._keys.clear()
        self._iid_to_row.clear()
        self.endResetModel()

    def set_row_status(self, iid: str, status: str) -> None:
        row_idx = self._iid_to_row.get(iid)
        if row_idx is None:
            return
        row = self._rows[row_idx]
        if row.status == status:
            return
        row.status = status
        index = self.index(row_idx, 2)
        self.dataChanged.emit(index, index, [Qt.ItemDataRole.DisplayRole])

    def mark_rows_status_if_current(self, iids: list[str], from_status: str, to_status: str) -> None:
        for iid in iids:
            row_idx = self._iid_to_row.get(iid)
            if row_idx is None:
                continue
            if self._rows[row_idx].status == from_status:
                self.set_row_status(iid, to_status)

    def item_count(self) -> int:
        return len(self._rows)

    def result_keys_in_order(self) -> list[tuple[str, str]]:
        return [(row.item_type, row.value) for row in self._rows]

    def collect_pending_entries(self) -> list[PendingScanEntry]:
        return [
            PendingScanEntry(iid=row.iid, kind=ScanTargetKind(row.item_type), value=row.value)
            for row in self._rows
            if row.status == "Pending"
        ]

    def undetected_files(self, iids: list[str] | None = None) -> list[tuple[str, str]]:
        if iids is None:
            rows = self._rows
        else:
            rows = [self._rows[self._iid_to_row[iid]] for iid in iids if iid in self._iid_to_row]
        return [
            (row.iid, row.value)
            for row in rows
            if row.item_type == ScanTargetKind.FILE and row.status == "Undetected"
        ]

    def get_iid_for_row(self, row: int) -> str | None:
        if 0 <= row < len(self._rows):
            return self._rows[row].iid
        return None

    def has_uploadable_undetected(self) -> bool:
        return any(row.item_type == ScanTargetKind.FILE and row.status == "Undetected" for row in self._rows)

    def _reindex(self) -> None:
        self._iid_to_row = {row.iid: idx for idx, row in enumerate(self._rows)}


class ResultsFilterProxyModel(QSortFilterProxyModel):
    _STATUS_RANKS: dict[str, int] = {
        "scanning...": 0,
        "uploading...": 0,
        "pending": 1,
        "error": 2,
        "malicious": 3,
        "uploaded - malicious": 3,
        "suspicious": 4,
        "uploaded - suspicious": 4,
        "undetected": 5,
        "clean": 6,
        "uploaded - clean": 6,
        "cancelled": 7,
    }

    def __init__(self, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._search_text = ""

    @Slot(str)
    def set_search_text(self, text: str) -> None:
        self._search_text = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(
        self,
        source_row: int,
        source_parent: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        if not self._search_text:
            return True
        model = self.sourceModel()
        if model is None:
            return True
        for column in range(model.columnCount()):
            index = model.index(source_row, column, source_parent)
            value = model.data(index, Qt.ItemDataRole.DisplayRole)
            if value is not None and self._search_text in str(value).lower():
                return True
        return False

    def lessThan(
        self,
        left: QModelIndex | QPersistentModelIndex,
        right: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        if left.column() == 2 and right.column() == 2:
            return self._status_sort_key(left.data()) < self._status_sort_key(right.data())
        return super().lessThan(left, right)

    @classmethod
    def _status_sort_key(cls, value: object) -> tuple[int, str]:
        text = str(value or "").strip().lower()
        return cls._STATUS_RANKS.get(text, 999), text


class UiState(QObject):
    api_status_changed = Signal(str)
    upload_indicator_changed = Signal(str)
    progress_text_changed = Signal(str)
    controls_enabled_changed = Signal(bool)
    scan_button_enabled_changed = Signal(bool)
    report_button_enabled_changed = Signal(bool)
    upload_button_visible_changed = Signal(bool)
    upload_button_enabled_changed = Signal(bool)
    progress_changed = Signal(int, int)
