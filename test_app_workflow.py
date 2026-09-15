"""GUI state tests using hidden Tk windows and no external services."""
import dataclasses
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock
import app


class AppWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.refresh = patch.object(app.App, "_refresh_models")
        self.refresh.start()
        self.addCleanup(self.refresh.stop)
        self.window = app.App()
        self.window.withdraw()
        self.addCleanup(self.window.destroy)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.window.url_var.set(self.temp.name)

    def test_run_snapshots_inputs_and_locks_controls(self):
        self.window.model_vars["stub"].set(True)
        with patch.object(app.threading, "Thread") as thread:
            self.window._run_bg(lambda: None, scan=True, requires_ai=True)
            thread.assert_called_once()
        self.assertTrue(self.window.busy)
        self.assertEqual(self.window.run_options.source, self.temp.name)
        self.assertEqual(self.window.run_options.models, ("stub",))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            self.window.run_options.max_files = 100
        self.assertEqual(self.window.b_ai.cget("state"), "disabled")
        self.assertEqual(self.window.b_cancel.cget("state"), "normal")
        self.window._set_busy(False)
        self.assertEqual(self.window.b_ai.cget("state"), "normal")

    def test_invalid_settings_do_not_start_worker(self):
        self.window.maxfiles.set(0)
        with patch.object(app.threading, "Thread") as thread, patch.object(app.messagebox, "showerror") as error:
            self.window.on_ai()
        thread.assert_not_called()
        error.assert_called_once()

    def test_no_model_prevents_download(self):
        with patch.object(app.threading, "Thread") as thread, patch.object(app.messagebox, "showerror") as error:
            self.window.on_ai()
        thread.assert_not_called()
        error.assert_called_once()

    def test_refresh_preserves_selection(self):
        self.window.model_vars["stub"].set(True)
        self.window._populate_models(({"stub"}, False))
        self.assertTrue(self.window.model_vars["stub"].get())

    def test_busy_close_cancels_without_killing_server(self):
        self.window._set_busy(True)
        with patch.object(app.M, "stop_ollama") as stop:
            self.window._on_close()
        self.assertTrue(self.window.cancel_event.is_set())
        self.assertTrue(self.window.closing)
        stop.assert_not_called()

    def test_stop_never_forces_shared_server(self):
        with patch.object(app.M, "stop_ollama", return_value=False) as stop:
            self.window._stop_server()
        stop.assert_called_once_with(force=False)

    def test_save_dialogs_wait_for_worker(self):
        self.window._set_busy(True)
        self.window.msg_q.put(("save", ("tmp.pdf", "review.pdf", "report"), None))
        with patch.object(self.window, "_save_dialog") as save:
            self.window._drain()
            save.assert_not_called()
            self.window._offer_reports()
            save.assert_not_called()
            self.window._set_busy(False)
            self.window._offer_reports()
            save.assert_called_once()

    def test_model_snapshot_does_not_unlock_before_worker_done(self):
        self.window._set_busy(True)
        self.window.msg_q.put(("models", ({"stub"}, False), None))
        self.window._drain()
        self.assertTrue(self.window.busy)
        self.window.msg_q.put(("done", None, None))
        self.window._drain()
        self.assertFalse(self.window.busy)
        self.assertIsNone(self.window._model_snapshot)

    def test_comparison_workflow_produces_three_reports_offline(self):
        from test_audit_reliability import CleanProvider
        root = Path(self.temp.name)
        (root / "a.py").write_text("def f(x):\n    return x\n")
        self.window.output_dir = root / "output"
        self.window.output_dir.mkdir()
        self.window.run_options = app.RunOptions(str(root), ("fake",), 6, 8)
        calibration = {"best_model": "fake", "best_strategy": "zero_shot", "best_f1": 1.0,
                       "per_model": {"fake": {"results": [], "n_samples": 8}}}
        static = {"languages": {"python": 1}, "tools_used": [], "per_tool": {},
                  "findings": [], "n_findings": 0, "scan_status": "failed", "tool_status": {}}
        with patch.object(app.SS, "calibrate_many", return_value=calibration), \
             patch.object(app.M, "get", return_value=CleanProvider()), \
             patch.object(app.RA, "triage_hints", return_value={}), \
             patch.object(app.RA.VI, "coverage_note", return_value="Synthetic test"), \
             patch.object(app.ST, "analyse", return_value=static), \
             patch.object(self.window, "_run_bg", side_effect=lambda fn, **kwargs: fn()):
            self.window.on_compare()
        self.assertEqual(len(list(self.window.output_dir.glob("*.pdf"))), 3)
        self.window._drain()
        self.assertEqual(len(self.window.pending_reports), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
