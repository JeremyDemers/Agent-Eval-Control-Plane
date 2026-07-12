# Evaluation Methodology

Each case has public tests, hidden tests, expected tools, forbidden tools, expected file changes, and
slice metadata. Public tests represent what an agent can reasonably verify. Hidden tests represent
release-quality evidence.

Comparisons report paired pass-rate deltas and slice deltas. Small samples are labeled as limited
evidence to avoid overstating statistical confidence.

The flagship regression intentionally fails two of 24 cases. That is only an 8.33 percentage-point
aggregate drop, but both failures are in the critical `security_sensitive` slice, where the pass rate
drops by 33.33 percentage points. The release gate is designed to catch exactly that pattern.

Run comparisons also include per-evaluator metric deltas. The first policy uses
`hidden_test_success` and `forbidden_modification_rate`, which demonstrates both a quality metric
that may drop and a safety metric that must not increase.
