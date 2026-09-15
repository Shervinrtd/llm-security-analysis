"""Repository Security Analyser — desktop application.

    python app.py

Paste a GitHub address, then run one of:

  * Safe to Clone?       a free, instant, deterministic scan for supply-chain
                         attacks (install hooks, hidden payloads, typosquats,
                         suspicious network calls). No model, no rate limit. It
                         answers "is it safe to DOWNLOAD this?" on its own.
  * Run AI Analysis      every prompting strategy is measured on labelled data,
                         the best one is selected, and the repository is scanned
                         with it. Reports two verdicts - safe to clone, and safe
                         to deploy - and names findings with CVE/CWE. -> PDF
  * Run Static Tools     detects the languages present, runs the matching static
                         analysers (Semgrep / Bandit / Gitleaks). -> PDF report
  * Compare AI vs Static runs both and reports where they agree and differ.
                         -> PDF report

The two questions are kept separate on purpose: a project can be safe to clone
(installing it runs nothing hostile) yet unsafe to deploy (its code has flaws),
or the reverse. Every report asks where to save it.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import tkinter as tk
import traceback
import urllib.request
import zipfile
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

import config as C                 # noqa: E402
import models as M                 # noqa: E402
import repo_analyze as RA          # noqa: E402
import static_tools as ST          # noqa: E402
import compare_analysis as CA      # noqa: E402
import pdf_report as PDF           # noqa: E402
import supply_chain as SUP         # noqa: E402
import strategy_select as SS       # noqa: E402
from audit import parse_github, download_repo   # noqa: E402
from audit_runtime import ScanCancelled, check_cancel

BG = "#0E2A31"; PANEL = "#143A44"; FG = "#EAF2F3"; MUT = "#9FBAC0"
ACCENT = "#F2A64B"; OK = "#35A28C"; WARN = "#E86A53"; FIELD = "#0B2229"


@dataclass(frozen=True)
class RunOptions:
    source: str
    models: tuple[str, ...]
    max_files: int
    calibration_samples: int


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Repository Security Analyser")
        self.geometry("1000x730")
        self.minsize(880, 640)
        self.configure(bg=BG)

        self.msg_q: queue.Queue = queue.Queue()
        self.busy = False
        self.last = {}                      # cached results of the last run
        self.cancel_event = threading.Event()
        self.closing = False
        self.pending_reports = []
        self.run_options = None
        self._model_snapshot = None
        self.output_dir = Path(tempfile.mkdtemp(prefix="security_reports_"))

        self._build_ui()
        self.after(100, self._drain)
        self.after(150, self._refresh_models)
        # Ollama's own autostart is disabled; the server is started on demand and
        # shut down again here, so nothing keeps running once you close the app.
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _on_close(self):
        if self.busy:
            self.closing = True
            self._cancel()
            self._log("Closing after the current request finishes. Other model sessions will be left running.", "warn")
            return
        try:
            if M.stop_ollama(force=False):
                print("local model server stopped")
        except Exception:
            pass
        self.destroy()

    # ------------------------------------------------------------------ UI
    def _build_ui(self):
        # header
        head = tk.Frame(self, bg=BG); head.pack(fill="x", padx=18, pady=(14, 6))
        tk.Label(head, text="Repository Security Analyser", bg=BG, fg=FG,
                 font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(head, text="AI-powered security auditing for open-source repositories",
                 bg=BG, fg=MUT, font=("Segoe UI", 9)).pack(anchor="w")

        # repo address
        box = tk.Frame(self, bg=PANEL); box.pack(fill="x", padx=18, pady=8)
        tk.Label(box, text="GitHub repository address", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(10, 2))
        row = tk.Frame(box, bg=PANEL); row.pack(fill="x", padx=12, pady=(0, 12))
        self.url_var = tk.StringVar(value="https://github.com/")
        e = tk.Entry(row, textvariable=self.url_var, font=("Consolas", 11),
                     bg=FIELD, fg=FG, insertbackground=FG, relief="flat")
        e.pack(side="left", fill="x", expand=True, ipady=7, padx=(0, 8))
        tk.Button(row, text="Local folder…", command=self._pick_folder, bg=PANEL, fg=MUT,
                  relief="flat", font=("Segoe UI", 9), cursor="hand2").pack(side="left")

        # options
        opt = tk.Frame(self, bg=BG); opt.pack(fill="x", padx=18, pady=(2, 6))

        mbox = tk.Frame(opt, bg=PANEL); mbox.pack(side="left", fill="both", expand=True, padx=(0, 8))
        hdr = tk.Frame(mbox, bg=PANEL); hdr.pack(fill="x", padx=12, pady=(10, 2))
        tk.Label(hdr, text="AI models - choose candidates for calibration",
                 bg=PANEL, fg=ACCENT, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Button(hdr, text="↻ refresh", command=self._refresh_models, bg=PANEL, fg=MUT,
                  relief="flat", font=("Segoe UI", 8), cursor="hand2").pack(side="right")

        # scrollable list (there are several models, each with its own controls)
        wrap = tk.Frame(mbox, bg=PANEL); wrap.pack(fill="both", expand=True, padx=12, pady=(0, 10))
        self.mcanvas = tk.Canvas(wrap, bg=PANEL, highlightthickness=0, height=185)
        msb = tk.Scrollbar(wrap, orient="vertical", command=self.mcanvas.yview)
        self.mlist = tk.Frame(self.mcanvas, bg=PANEL)
        self.mlist.bind("<Configure>",
                        lambda e: self.mcanvas.configure(scrollregion=self.mcanvas.bbox("all")))
        self.mcanvas.create_window((0, 0), window=self.mlist, anchor="nw")
        self.mcanvas.configure(yscrollcommand=msb.set)
        self.mcanvas.pack(side="left", fill="both", expand=True)
        msb.pack(side="right", fill="y")
        self.mcanvas.bind("<MouseWheel>",
                              lambda e: self.mcanvas.yview_scroll(int(-e.delta / 120), "units"))

        self.model_vars = {}
        self.key_vars = {}
        self._populate_models()

        sbox = tk.Frame(opt, bg=PANEL); sbox.pack(side="left", fill="both")
        tk.Label(sbox, text="Settings", bg=PANEL, fg=ACCENT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=12, pady=(10, 4))
        f2 = tk.Frame(sbox, bg=PANEL); f2.pack(fill="x", padx=12, pady=(0, 10))
        tk.Label(f2, text="Max files to scan:", bg=PANEL, fg=FG,
                 font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w")
        self.maxfiles = tk.IntVar(value=6)
        tk.Spinbox(f2, from_=1, to=200, textvariable=self.maxfiles, width=6,
                   bg=FIELD, fg=FG, relief="flat").grid(row=0, column=1, padx=6)
        tk.Label(f2, text="Calibration samples:", bg=PANEL, fg=FG,
                 font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", pady=(6, 0))
        self.calib_n = tk.IntVar(value=8)
        tk.Spinbox(f2, from_=4, to=60, textvariable=self.calib_n, width=6,
                   bg=FIELD, fg=FG, relief="flat").grid(row=1, column=1, padx=6, pady=(6, 0))
        tk.Label(f2, text="(higher = more AI calls)", bg=PANEL, fg=MUT,
                 font=("Segoe UI", 8)).grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))

        # action buttons. The clone-safety check comes first: it is free, instant,
        # needs no model, and answers the most important question on its own.
        btns = tk.Frame(self, bg=BG); btns.pack(fill="x", padx=18, pady=10)
        self.b_clone = self._btn(btns, "Supply-chain check", "#2A8C79", self.on_clone)
        self.b_ai = self._btn(btns, "AI analysis", OK, self.on_ai)
        self.b_static = self._btn(btns, "Static tools", "#3E7CB1", self.on_static)
        self.b_cmp = self._btn(btns, "Compare", ACCENT, self.on_compare, fg="#1A1A1A")
        self.b_cancel = self._btn(btns, "Cancel", WARN, self._cancel)
        self.b_cancel.configure(state="disabled")

        # log
        tk.Label(self, text="Progress", bg=BG, fg=ACCENT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18)
        lf = tk.Frame(self, bg=BG); lf.pack(fill="both", expand=True, padx=18, pady=(2, 6))
        self.log = tk.Text(lf, bg=FIELD, fg=FG, font=("Consolas", 9), relief="flat",
                           wrap="word", insertbackground=FG, height=8)
        sb = tk.Scrollbar(lf, command=self.log.yview); sb.pack(side="right", fill="y")
        self.log.configure(yscrollcommand=sb.set); self.log.pack(fill="both", expand=True)
        for tag, col in (("ok", OK), ("warn", ACCENT), ("err", WARN), ("mut", MUT)):
            self.log.tag_config(tag, foreground=col)

        self.status = tk.Label(self, text="Ready", bg=BG, fg=MUT, anchor="w",
                               font=("Segoe UI", 9))
        self.status.pack(fill="x", padx=18, pady=(0, 10))

        self._log("Ready. Paste a GitHub address above and choose an action.", "mut")
        self._log("Model availability will be checked in the background. A key being set does not confirm provider quota.", "mut")

    # ------------------------------------------------------------ model list
    def _populate_models(self, snapshot=None):
        """Draw one row per model: local ones get a Download button, cloud ones
        get an API-key box. Rebuilt whenever availability changes."""
        selected = {name: var.get() for name, var in self.model_vars.items()}
        for w in self.mlist.winfo_children():
            w.destroy()
        avail, up = snapshot if snapshot is not None else ({"stub"}, False)

        local = [(n, p) for n, p in M.REGISTRY.items() if p.kind == "ollama"]
        cloud = [(n, p) for n, p in M.REGISTRY.items() if p.kind not in ("ollama", "stub")]
        stub = [(n, p) for n, p in M.REGISTRY.items() if p.kind == "stub"]

        def section(title, note):
            f = tk.Frame(self.mlist, bg=PANEL); f.pack(fill="x", pady=(8, 2))
            tk.Label(f, text=title, bg=PANEL, fg=FG,
                     font=("Segoe UI", 9, "bold")).pack(side="left")
            tk.Label(f, text=note, bg=PANEL, fg=MUT,
                     font=("Segoe UI", 8)).pack(side="left", padx=(6, 0))

        # ---------------- local ----------------
        section("Local models", "— no API key, no rate limits, run on this PC")
        srv = tk.Frame(self.mlist, bg=PANEL); srv.pack(fill="x", pady=(0, 2))
        tk.Label(srv, text="      server:", bg=PANEL, fg=MUT,
                 font=("Segoe UI", 8)).pack(side="left")
        tk.Label(srv, text=("● running" if up else "○ off (starts automatically when used)"),
                 bg=PANEL, fg=(OK if up else MUT), font=("Segoe UI", 8)).pack(side="left", padx=4)
        if up:
            tk.Button(srv, text="stop now", command=self._stop_server, bg=PANEL, fg=MUT,
                      relief="flat", font=("Segoe UI", 8), cursor="hand2").pack(side="left")
        for name, p in local:
            row = tk.Frame(self.mlist, bg=PANEL); row.pack(fill="x", pady=1)
            ready = name in avail
            v = tk.BooleanVar(value=ready and selected.get(name, False))
            self.model_vars[name] = v
            tk.Checkbutton(row, text="", variable=v, bg=PANEL, selectcolor=FIELD,
                           activebackground=PANEL,
                           state=("normal" if ready else "disabled")).pack(side="left")
            tk.Label(row, text=name, bg=PANEL, fg=(FG if ready else "#5E7A80"),
                     font=("Segoe UI", 9), width=24, anchor="w").pack(side="left")
            if p.vendor:
                tk.Label(row, text=p.vendor, bg=PANEL, fg=ACCENT,
                         font=("Segoe UI", 8), width=9, anchor="w").pack(side="left")
            if ready:
                tk.Label(row, text="● ready", bg=PANEL, fg=OK,
                         font=("Segoe UI", 8)).pack(side="left")
            else:
                tk.Label(row, text="not downloaded", bg=PANEL, fg=MUT,
                         font=("Segoe UI", 8)).pack(side="left")
                tk.Button(row, text="Download", bg="#3E7CB1", fg="#FFFFFF", relief="flat",
                          font=("Segoe UI", 8), cursor="hand2", padx=8,
                          command=lambda m=p.model: self._download_model(m)).pack(side="left", padx=6)

        # ---------------- cloud ----------------
        section("Cloud models", "— need a free API key (paste it below)")
        for name, p in cloud:
            row = tk.Frame(self.mlist, bg=PANEL); row.pack(fill="x", pady=1)
            ready = name in avail
            v = tk.BooleanVar(value=ready and selected.get(name, False))
            self.model_vars[name] = v
            tk.Checkbutton(row, text="", variable=v, bg=PANEL, selectcolor=FIELD,
                           activebackground=PANEL,
                           state=("normal" if ready else "disabled")).pack(side="left")
            tk.Label(row, text=name, bg=PANEL, fg=(FG if ready else "#5E7A80"),
                     font=("Segoe UI", 9), width=15, anchor="w").pack(side="left")
            if p.vendor:
                tk.Label(row, text=p.vendor, bg=PANEL, fg=ACCENT,
                         font=("Segoe UI", 8), width=8, anchor="w").pack(side="left")

            kv = self.key_vars.get(p.env_key) or tk.StringVar()
            self.key_vars[p.env_key] = kv
            ent = tk.Entry(row, textvariable=kv, show="•", width=18, bg=FIELD, fg=FG,
                           insertbackground=FG, relief="flat", font=("Consolas", 9))
            ent.pack(side="left", ipady=3, padx=(0, 4))
            if ready:
                ent.insert(0, "")                       # never display a stored key
            tk.Button(row, text="Save", bg=OK if not ready else PANEL,
                      fg="#FFFFFF" if not ready else MUT, relief="flat",
                      font=("Segoe UI", 8), cursor="hand2", padx=8,
                      command=lambda e=p.env_key, var=kv: self._save_key(e, var)
                      ).pack(side="left")
            tk.Label(row, text=("● key set" if ready else p.env_key), bg=PANEL,
                     fg=(OK if ready else MUT), font=("Segoe UI", 8)).pack(side="left", padx=6)

        # ---------------- offline test ----------------
        section("Offline self-test", "— fake answers, for checking the app works")
        for name, p in stub:
            row = tk.Frame(self.mlist, bg=PANEL); row.pack(fill="x", pady=1)
            v = tk.BooleanVar(value=selected.get(name, False))
            self.model_vars[name] = v
            tk.Checkbutton(row, text="", variable=v, bg=PANEL, selectcolor=FIELD,
                           activebackground=PANEL).pack(side="left")
            tk.Label(row, text=name, bg=PANEL, fg=MUT,
                     font=("Segoe UI", 9), anchor="w").pack(side="left")

    def _refresh_models(self):
        if self.busy:
            return
        def job():
            M.refresh()
            downloaded = set(M.ollama_models())
            avail = {n for n, p in M.REGISTRY.items() if p.kind == "stub" or
                     (p.kind == "ollama" and (p.model in downloaded or
                       (":" not in p.model and any(m.split(":")[0] == p.model for m in downloaded)))) or
                     (p.kind not in ("stub", "ollama") and bool(p.api_key))}
            self.msg_q.put(("models", (avail, M._ollama_up()), None))
            self._log("Model list refreshed.", "mut")
        self._run_bg(job)

    def _stop_server(self):
        if self.busy:
            return
        if M.stop_ollama(force=False):
            self._log("Local model server stopped. It will start again automatically "
                      "the next time a local model is used.", "ok")
        else:
            self._log("The local server was not started by this app, so it was left alone. "
                      "(Close it from the Ollama tray icon if you want it off.)", "warn")
        self._refresh_models()

    def _save_key(self, env_var: str, var: tk.StringVar):
        val = var.get().strip()
        if not val:
            self._log(f"{env_var}: nothing entered — paste the key first.", "warn")
            return
        try:
            M.set_api_key(env_var, val)       # written to .env, never logged
            var.set("")
            self._log(f"{env_var} saved to .env ({len(val)} characters). Key value is not shown or logged.", "ok")
            self._refresh_models()
        except Exception as e:
            messagebox.showerror("Could not save key", str(e))

    def _download_model(self, model: str):
        if self.busy:
            return
        def job():
            self._log(f"Downloading local model '{model}' — this can take several minutes…", "warn")
            self._set_status(f"Downloading {model}…")
            ok = M.ollama_pull(model, on_line=lambda l: self._log("   " + l, "mut"))
            if ok:
                self._log(f"'{model}' downloaded and ready.", "ok")
            else:
                self._log(f"Download of '{model}' failed. Is Ollama installed and running?", "err")
            self.msg_q.put(("repopulate", None, None))
        self._run_bg(job)

    def _btn(self, parent, text, colour, cmd, fg="#FFFFFF"):
        b = tk.Button(parent, text=text, command=cmd, bg=colour, fg=fg, relief="flat",
                      font=("Segoe UI", 10, "bold"), cursor="hand2",
                      activebackground=colour, padx=14, pady=10)
        b.pack(side="left", padx=(0, 10))
        return b

    # --------------------------------------------------------------- helpers
    def _pick_folder(self):
        d = filedialog.askdirectory(title="Choose a local repository folder")
        if d:
            self.url_var.set(d)

    def _log(self, text, tag=None):
        self.msg_q.put(("log", text, tag))

    def _set_status(self, text):
        self.msg_q.put(("status", text, None))

    def _drain(self):
        while True:
            try:
                kind, text, tag = self.msg_q.get_nowait()
            except queue.Empty:
                break
            if kind == "log":
                self.log.insert("end", text + "\n", tag or ())
                self.log.see("end")
            elif kind == "status":
                self.status.configure(text=text)
            elif kind == "done":
                self._set_busy(False)
                if self._model_snapshot is not None:
                    self._populate_models(self._model_snapshot)
                    self._model_snapshot = None
                if self.closing:
                    self._on_close()
                    return
                self.after_idle(self._offer_reports)
            elif kind == "save":
                self.pending_reports.append(text)
            elif kind == "repopulate":
                self.after(200, self._refresh_models)
            elif kind == "models":
                self._model_snapshot = text
        self.after(100, self._drain)

    def _set_busy(self, busy: bool):
        self.busy = busy
        if busy:
            self._disabled_controls = []
            def lock(parent):
                for child in parent.winfo_children():
                    if child is self.b_cancel:
                        continue
                    if isinstance(child, (tk.Button, tk.Entry, tk.Spinbox, tk.Checkbutton)):
                        self._disabled_controls.append((child, child.cget("state")))
                        child.configure(state="disabled")
                    lock(child)
            lock(self)
        else:
            for widget, state in getattr(self, "_disabled_controls", []):
                if widget.winfo_exists():
                    widget.configure(state=state)
            self._disabled_controls = []
        self.b_cancel.configure(state="normal" if busy else "disabled")
        if not busy:
            self.status.configure(text="Ready")

    def _cancel(self):
        self.cancel_event.set()
        self.b_cancel.configure(state="disabled")
        self._set_status("Cancellation requested; waiting for the current request or tool to finish...")

    def _offer_reports(self):
        if self.busy or self.closing:
            return
        reports, self.pending_reports = self.pending_reports, []
        for report in reports:
            self._save_dialog(*report)

    def _save_dialog(self, tmp_pdf: str, suggested: str, label: str):
        dest = filedialog.asksaveasfilename(
            title=f"Save {label}", defaultextension=".pdf",
            initialfile=suggested, filetypes=[("PDF document", "*.pdf")])
        if not dest:
            self._log(f"{label}: save cancelled (a copy remains at {tmp_pdf})", "warn")
            return
        try:
            shutil.copyfile(tmp_pdf, dest)
            self._log(f"{label} saved to: {dest}", "ok")
            try:
                if sys.platform.startswith("win"):
                    os.startfile(dest)
            except Exception:
                pass
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _selected_models(self):
        return [n for n, v in self.model_vars.items() if v.get()]

    def _resolve_source(self, tmp: Path):
        """Return (root_path, display_name) for the address in the box."""
        raw = self.run_options.source
        if not raw or raw == "https://github.com/":
            raise ValueError("Please paste a GitHub repository address first.")
        p = Path(raw)
        if p.is_dir():
            self._log(f"Using local folder: {p}", "mut")
            return p, p.name
        parsed = parse_github(raw)
        if not parsed:
            raise ValueError(f"Not a GitHub address: {raw}")
        owner, repo = parsed
        self._log(f"Downloading github.com/{owner}/{repo} ...", "mut")
        root = download_repo(owner, repo, tmp, verbose=False)
        if root is None:
            raise RuntimeError("Could not download the repository. Is it public?")
        self._log("Download complete.", "ok")
        return root, f"{owner}/{repo}"

    def _run_bg(self, fn, scan=False, requires_ai=False):
        if self.busy:
            return
        if scan:
            try:
                source = self.url_var.get().strip()
                if not source or source == "https://github.com/":
                    raise ValueError("Choose a local folder or enter a GitHub repository address.")
                if not Path(source).is_dir() and not parse_github(source):
                    raise ValueError("Enter a valid local folder or GitHub repository address.")
                max_files, samples = self.maxfiles.get(), self.calib_n.get()
                if not 1 <= max_files <= 200 or not 4 <= samples <= 60:
                    raise ValueError("Files must be 1-200; calibration samples must be 4-60.")
                models = tuple(self._selected_models())
                if requires_ai and not models:
                    raise ValueError("Select at least one AI model.")
                if "stub" in models and len(models) > 1:
                    raise ValueError("Run the offline demo separately from real models.")
                self.run_options = RunOptions(source, models, max_files, samples)
            except (ValueError, tk.TclError) as exc:
                messagebox.showerror("Check scan settings", str(exc))
                return
            self.last = {}
            self.output_dir = Path(tempfile.mkdtemp(prefix="security_reports_"))
        self.cancel_event.clear()
        self._set_busy(True)
        threading.Thread(target=self._guard(fn), daemon=True).start()

    def _guard(self, fn):
        def wrapper():
            try:
                fn()
            except ScanCancelled:
                self._log("Scan cancelled. Completed reports, if any, are still available to save.", "warn")
            except Exception as e:
                self._log(f"Run failed ({type(e).__name__}). Check the source, provider availability and scan settings.", "err")
            finally:
                self.msg_q.put(("done", None, None))
        return wrapper

    # ---------------------------------------------------------- AI analysis
    def _do_ai(self, root: Path, name: str):
        check_cancel(self.cancel_event)
        models = list(self.run_options.models)
        if not models:
            raise ValueError("Select at least one AI model.")

        # 1. measure every prompting strategy on labelled data, pick the winner
        self._log("", None)
        self._log("STEP 1 — comparing prompting strategies on labelled benchmark data", "warn")
        self._set_status("Calibrating prompting strategies…")
        calib = SS.calibrate_many(models, n_samples=self.run_options.calibration_samples,
                                  progress=lambda m: self._log("   " + m, "mut"), cancel_event=self.cancel_event)
        best_model = calib.get("best_model")
        if not best_model:
            raise ValueError("No model completed calibration successfully.")
        best_strategy = calib.get("best_strategy") or "zero_shot"
        self._log(f"   -> best combination: {best_model} + '{best_strategy}' "
                  f"(F1={calib.get('best_f1', 0):.3f})", "ok")

        # 2. scan the repository with the winner
        self._log("")
        self._log(f"STEP 2 — scanning repository with {best_model} / {best_strategy}", "warn")
        self._set_status("Analysing repository with AI…")
        ls = self._label_space()
        provider = M.get(best_model)
        # `name` is "owner/repo" for a GitHub address: it lets a finding be matched
        # against that project's own CVE history, not just against exact code
        rep = RA.analyse_repo(root, provider, ls, best_strategy,
                              max_files=self.run_options.max_files, verbose=False,
                              repo_slug=name if "/" in name else None,
                              progress=lambda m: self._log(m, "mut"), cancel_event=self.cancel_event)
        d = rep.__dict__
        self.last["ai"] = d
        self.last["model"] = best_model
        self.last["strategy"] = best_strategy
        self.last["calib"] = calib.get("per_model", {}).get(best_model)

        clone = d.get("clone_safety", "unknown")
        self._log("")
        self._log(f"   SUPPLY-CHAIN RESULT: {clone.upper()}",
                  "err" if clone == "dangerous" else "warn" if clone in ("caution", "unknown") else "ok")
        self._log(f"      {d.get('clone_reason', '')}", "mut")
        self._log(f"   FINDING RISK: {d['risk_level'].upper()}  |  findings: {len(d['findings'])}",
                  "err" if d["risk_level"] in ("critical", "high") else "ok")
        tiers = d.get("by_tier") or {}
        self._log(f"      evidence: {tiers.get('A', 0)} database / pattern match(es), "
                  f"{tiers.get('C', 0)} model opinion(s)", "mut")
        for pillar, n in (d.get("by_pillar") or {}).items():
            self._log(f"     {pillar}: {n}", "mut")
        nov = d.get("by_novelty") or {}
        if nov:
            self._log(f"   named with a CVE/GHSA id: {d.get('identified', 0)}", "ok")
            for key, label in (("known", "already published (known CVE)"),
                               ("known_location", "function has CVE history"),
                               ("novel", "no published match - investigate"),
                               ("unconfirmed", "no advisory data either way")):
                if nov.get(key):
                    self._log(f"     {label}: {nov[key]}", "mut")

        # 3. PDF
        self._log(f"   Scan coverage: {d['coverage']['status']} - {d['n_analysed']} of {d['n_files']} eligible files", "warn" if d['coverage']['status'] != "complete" else "ok")
        out = self.output_dir / f"ai_report_{name.replace('/', '_')}.pdf"
        PDF.build_ai_report(out, name, d, self.last["calib"], best_model, best_strategy)
        self.msg_q.put(("save", (str(out), f"AI_report_{name.replace('/', '_')}.pdf",
                                 "AI analysis report"), None))

    def on_ai(self):
        def job():
            tmp = Path(tempfile.mkdtemp(prefix="rsa_"))
            try:
                root, name = self._resolve_source(tmp)
                self._do_ai(root, name)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        self._run_bg(job, scan=True, requires_ai=True)

    # ------------------------------------------------------ static analysis
    def _do_static(self, root: Path, name: str):
        self._log("")
        self._log("STATIC ANALYSIS — detecting languages and selecting tools", "warn")
        self._set_status("Running static analysis tools…")
        check_cancel(self.cancel_event)
        res = ST.analyse(root, progress=lambda m: self._log("   " + m, "mut"), cancel_event=self.cancel_event)
        check_cancel(self.cancel_event)
        self.last["static"] = res
        langs = ", ".join(f"{k} ({v})" for k, v in
                          sorted(res["languages"].items(), key=lambda kv: -kv[1])) or "none"
        self._log(f"   languages detected: {langs}", "ok")
        self._log(f"   tools selected: {', '.join(res['tools_used'])}", "ok")
        for t, n in res["per_tool"].items():
            self._log(f"     {t}: {n} finding(s)", "mut")
        self._log(f"   Static scan status: {res.get('scan_status', 'unknown')}", "mut")
        out = self.output_dir / f"static_report_{name.replace('/', '_')}.pdf"
        PDF.build_static_report(out, name, res)
        self.msg_q.put(("save", (str(out), f"Static_report_{name.replace('/', '_')}.pdf",
                                 "static analysis report"), None))

    def on_static(self):
        def job():
            tmp = Path(tempfile.mkdtemp(prefix="rsa_"))
            try:
                root, name = self._resolve_source(tmp)
                self._do_static(root, name)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        self._run_bg(job, scan=True)

    # ------------------------------------------------------ clone safety
    def _do_clone(self, root: Path, name: str):
        self._log("")
        self._log("CLONE-SAFETY CHECK — deterministic, no AI, no rate limit", "warn")
        self._set_status("Scanning for supply-chain attack indicators…")
        res = SUP.analyse(root, cancel_event=self.cancel_event)
        self.last["supply"] = res
        crit = [f for f in res["findings"] if f["severity"] == "CRITICAL"]
        high = [f for f in res["findings"] if f["severity"] == "HIGH"]
        if crit:
            self._log("   RESULT: REVIEW BEFORE INSTALLING OR RUNNING", "err")
            self._log(f"      {len(crit)} high-risk pattern match(es); confirm the context.", "err")
        elif high:
            self._log("   RESULT: CLONE WITH CAUTION", "warn")
            self._log(f"      {len(high)} concern(s) to review before installing.", "warn")
        else:
            self._log("   RESULT: " + ("NO HIGH-RISK PATTERNS FOUND" if res["status"] == "complete" else "COVERAGE INCOMPLETE"), "warn")
            self._log("      This pattern scan does not establish that installation or execution is safe.", "mut")
        for f in res["findings"][:12]:
            tag = {"install_hook": "install hook", "obfuscation": "hidden payload",
                   "network": "network", "typosquat": "typosquat",
                   "ci_risk": "CI risk"}.get(f.get("kind"), f.get("kind", ""))
            self._log(f"     [{f['severity']}] {tag}: {f['file']}", "mut")
        out = self.output_dir / f"clone_safety_{name.replace('/', '_')}.pdf"
        PDF.build_clone_report(out, name, res)
        self.msg_q.put(("save", (str(out), f"CloneSafety_{name.replace('/', '_')}.pdf",
                                 "clone-safety report"), None))

    def on_clone(self):
        def job():
            tmp = Path(tempfile.mkdtemp(prefix="rsa_"))
            try:
                root, name = self._resolve_source(tmp)
                self._do_clone(root, name)
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        self._run_bg(job, scan=True)

    # ---------------------------------------------------------- comparison
    def on_compare(self):
        def job():
            tmp = Path(tempfile.mkdtemp(prefix="rsa_"))
            try:
                root, name = self._resolve_source(tmp)
                self._do_ai(root, name)
                self._do_static(root, name)
                self._log("")
                self._log("COMPARISON — AI vs static tools", "warn")
                cmp = CA.compare(self.last["ai"], self.last["static"],
                                 self.last.get("model", ""), self.last.get("strategy", ""))
                for line in CA.summary_text(cmp).splitlines():
                    self._log("   " + line, "ok")
                check_cancel(self.cancel_event)
                out = self.output_dir / f"comparison_{name.replace('/', '_')}.pdf"
                PDF.build_comparison_report(out, name, cmp)
                self.msg_q.put(("save", (str(out), f"Comparison_{name.replace('/', '_')}.pdf",
                                         "comparison report"), None))
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        self._run_bg(job, scan=True, requires_ai=True)

    # --------------------------------------------------------------- misc
    @staticmethod
    def _label_space():
        p = C.PROCESSED / "label_space.json"
        if p.exists():
            return json.loads(p.read_text(encoding="utf-8"))
        return {"classes": [], "prompt_block": ""}


if __name__ == "__main__":
    App().mainloop()
