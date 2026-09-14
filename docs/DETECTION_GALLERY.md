# Synthetic detection gallery

Eight synthetic examples of supported rules, not independent real-world detection accuracy.

| Example | Deterministic score | Hybrid score | Expected high priority |
| --- | --- | --- | --- |
| Routine process | 3.0 | 4.631 | False |
| Ordinary file change | 2.0 | 7.035 | False |
| Single authentication failure | 8.0 | 11.406 | False |
| Loopback listener | 28.0 | 24.664 | False |
| Synthetic scanner detection | 100.0 | 100.0 | True |
| Reverse-shell marker | 65.0 | 55.291 | True |
| Credential spray | 69.0 | 67.66 | True |
| Evidence integrity failure | 90.0 | 77.435 | True |

Threshold: 65. No host scan or action execution. Use --json for reasons and synthetic confusion counts.
