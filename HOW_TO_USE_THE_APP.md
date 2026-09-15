# Repository Security Analyser

Start from this folder with `python app.py` using the Python environment that has the project dependencies installed.

## Choose what to check

Enter a public GitHub repository address or choose **Local folder**. Wait for model availability to refresh, then select the models you want to compare. A saved API key does not establish that its provider currently has quota or that the key is valid.

- **Supply-chain check** scans supported text files for suspicious installation, obfuscation, network and dependency-name patterns. It requires no model. Review a match in context; it is not proof of an attack.
- **AI analysis** calibrates candidate vulnerability strategies on validation samples, scans a limited set of files with the chosen model, and includes a supply-chain pass.
- **Static tools** runs the applicable installed Semgrep, Bandit and Gitleaks tools. The report shows each tool's completion or failure status.
- **Compare** runs AI and static analysis and prepares three PDFs: the two individual reports and a finding-overlap report. Overlap is not an accuracy score.

## Settings and progress

**Max files to scan** limits the AI budget; it does not limit all static tools. Start with a small budget and read the coverage section before interpreting the results. Vulnerability analysis also has a 12-function-per-file limit.

**Calibration samples** controls how many labelled validation records are used to choose a strategy. The default eight samples give only a rough ranking. Those scores are not accuracy estimates for the repository you are scanning. The other analysis categories use their own fixed prompts.

Inputs are locked during work. **Cancel** requests a stop after the current model request or external tool finishes. This can take time; it does not force-kill shared model services. Closing during a scan also waits for that boundary.

The offline **stub** option uses fake responses for demonstration and must be selected separately from real models. Its PDFs are labelled as demonstrations.

## Read and save the reports

Save dialogs appear after processing finishes. A cancelled save leaves a temporary copy at the location shown in the progress log. Each run has a separate report directory.

Read the completion status and coverage first. **Unknown**, **partial** or **failed** does not mean clean. Zero findings from a failed check are not a negative security result. Even completed checks only cover the stated scope.

Findings include location, category, severity, evidence and a next action. Credentials are redacted. A model opinion is unverified; a database match still needs applicability checks; a supply-chain pattern does not establish malicious intent. All findings are included in the PDF.

The comparison matches compatible classifications at nearby locations, one-to-one. An unmatched static finding in a file the AI did not fully inspect is not an AI miss.

The report previews in `output/report-previews/` are synthetic examples of the revised layout. See `RELIABILITY_UPDATE.md` for changes, validation and remaining limitations.
