# Internship

## Abstract

Open-source software hosted on platforms such as GitHub has become a fundamental component of modern software systems, enabling rapid development and widespread collaboration. However, the public availability of source code and the extensive reuse of third-party components introduce significant cybersecurity risks, including malware insertion, vulnerable dependencies, exposed secrets, and software supply-chain attacks. Traditional security analysis tools, such as signature-based scanners and static application security testing (SAST) tools, are effective at detecting known vulnerabilities but often struggle to identify novel threats, obfuscated malicious logic, or context-dependent security flaws due to rigid, rule-based matching boundaries (Al-Mansoori et al., 2025; Tamberg & Bahsi, 2025).

This work investigates the use of Large Language Models (LLMs), developed by organizations such as OpenAI, Google, and Meta Platforms, as advanced semantic analyzers for automated security assessment of open-source software repositories. Leveraging their ability to understand programming languages, complex code structure, and developer intent, LLMs are employed to scan source code for indicators of malicious behavior, vulnerabilities, insecure coding practices, and sensitive data exposure (Sheng et al., 2025). The proposed approach integrates repository collection, code preprocessing, prompt-based analysis, and risk classification to produce comprehensive security reports (Ahmed et al., 2025).

An experimental evaluation is conducted on a diverse set of public repositories to assess the effectiveness of LLM-based detection compared with conventional tools. The study examines detection capability, false positives, interpretability of results, and the ability to identify previously unseen threats. Particular attention is given to malware patterns such as backdoors, data exfiltration routines, and suspicious network activity, as well as common vulnerabilities including injection flaws and authentication weaknesses.  

Empirical results available in the literature demonstrate that while traditional SAST tools suffer from rigid rule restrictions leading to persistent false alarms, LLMs achieve significantly higher mean F1-scores—often driven by superior contextual recall across intricate code pathways (Dubniczky et al., 2025; Gnieciak & Szandała, 2025). Nevertheless, challenges remain regarding standalone deployment, as LLMs exhibit higher false-positive ratios, suffer from tokenization artifacts that skew line-localization precision, and demonstrate performance degradation when scaling to large repositories (Dubniczky et al., 2025; Gnieciak & Szandała, 2025; Steenhoek et al., 2024). This research highlights the immense potential of AI-driven techniques to complement existing security mechanisms through context-aware triage, supporting the integration of hybrid, neuro-symbolic LLM-augmented frameworks into future automated security auditing workflows (Li et al., 2025).  

## References

Ahmed, M. B. U., Harzevili, N. S., Shin, J., Pham, H. V., & Wang, S. (2025). SecVulEval: Benchmarking LLMs for Real-World C/C++ Vulnerability Detection. arXiv preprint arXiv:2505.19828.

Al-Mansoori, S., et al. (2025). LLM vs. SAST: A Technical Analysis on Detecting Coding Bugs of GPT4-Advanced Data Analysis. arXiv preprint arXiv:2506.15212.

Li, Z. et all (2025). IRIS: LLM-Assisted Static Analysis for Detecting Security Vulnerabilities. International Conference on Learning Representations (ICLR).

Dubniczky, R. A., Horvát, K. Z., Bisztray, T., Ferrag, M. A., Cordeiro, L. C., & Tihanyi, N. (2025). CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE Detection. arXiv preprint arXiv:2503.09433.  

Gnieciak, D., & Szandała, T. (2025). Large Language Models Versus Static Code Analysis Tools: A Systematic Benchmark for Vulnerability Detection. IEEE Access, 13, 198410-198422.  

Sheng, Z., Chen, Z., Gu, S., Huang, H., Gu, G., & Huang, J. (2025). LLMs in Software Security: A Survey of Vulnerability Detection Techniques and Insights. arXiv preprint arXiv:2502.07049.

Steenhoek, B., Rahman, M. M., Roy, M. K., Alam, M. S., Tong, H., Das, S., Barr, E. T., & Le, W. (2024). To Err is Machine: Vulnerability Detection Challenges LLM Reasoning. arXiv preprint arXiv:2403.17218.

Tamberg, K., & Bahsi, H. (2025). Harnessing Large Language Models for Software Vulnerability Detection: A Comprehensive Benchmarking Study. IEEE Access, 13, 29698–29717.
