from __future__ import annotations

from gui.workflows import upload_completion_feedback


def test_upload_completion_feedback_success() -> None:
    progress, title, message, style = upload_completion_feedback(3, 0)
    assert progress == "Upload complete"
    assert title == "Upload Complete"
    assert message == "Uploaded 3 file(s)."
    assert style == "success"


def test_upload_completion_feedback_errors() -> None:
    progress, title, message, style = upload_completion_feedback(3, 1)
    assert progress == "Upload finished with errors"
    assert title == "Upload Finished With Errors"
    assert message == "Uploaded 2/3 file(s); 1 failed."
    assert style == "warning"
