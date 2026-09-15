# Project limitations: required fixes and scientific boundaries

The comprehensive project report explains the delivered system and evidence. It is not a narrative of successive edits. Historical audit logs remain separate for traceability.

## Fixes needed for valid measurement

- **Sample identity:** content-backed IDs and duplicate rejection are implemented. Historical ambiguous rows are explicitly excluded; their predictions cannot be reassigned by guesswork.
- **Selection instrumentation:** the deployed selected paths are recorded and the completed 56-case rerun has a consistent trace. File-level alarm hits are no longer represented as independently verified defect detections.
- **Malformed perturbations:** the reported valid Python experiment uses static AST validation. The combined intervention also changes formatting; a same-identity reserialisation-only control is executed to distinguish this from additional literal splitting.
- **Missing finding evidence:** future repository benchmark rows now retain `findings` with their existing coverage record. This enables subsequent adjudication; it does not recover explanations absent from earlier results.
- **Failure interpretation:** invalid replies and failed tool checks remain failures, not negative security predictions. Paired completeness is reported.
- **Unlisted dependency names:** all-reported scoring additionally counts these predictions as false positives.
- **Reporting:** the main project report presents final measurements with their operational definitions; methodology history is kept in supporting records.

## Limits that need new evidence rather than an automatic code fix

- Independent human review of positive and negative dataset labels, the target-file alarm cases and explanation usefulness.
- A matched conventional vulnerability baseline evaluated on common eligible inputs and adjudicated targets.
- New held-out repository and threat-family samples, with no subsequent tuning on the reported test set.
- Further models and transformations where a specific generalisation claim warrants the cost.

These are not silently declared solved. Their absence limits the claims, but does not prevent an honest report of the implementation and completed experiments. The internship programme does not require a particular score or unlimited research scope; tutors decide whether the delivered investigation is sufficient.

## Intrinsic or presently unrecoverable boundaries

- Repository disjointness cannot establish complete absence from a proprietary model's training data.
- Missing historical snapshots, invocation logs and finding details cannot be reconstructed with certainty from aggregate metrics.
- AST agreement does not cover every observable behaviour, particularly source introspection.
- Synthetic samples and family variants do not establish population performance on real repositories.

## Verification

The formatting control completed all 339 pairs for Qwen and YARA with no failed pairs. Source hashes, reserialised content hashes and AST preservation validate. Repeated original verdicts agree with the combined run; reserialised-only and reserialised-plus-splitting verdicts are identical for all items under each detector. Both Qwen changes are already present under reserialisation alone, so no additional benefit is attributable to literal splitting in this sample. The control reused 366 of 678 Qwen responses and is not an independent replication.

The current offline suite has 58 passing tests, including a control-AST preservation check. New report builds require the explicitly pinned formatting-control run to be complete, compare matched identities, verify source/fixture hashes and recorded model/rule configurations, and recompute its summary from raw predictions. The report records any repeated-original disagreement so a sequential control is not mistaken for a randomised independent repetition.
