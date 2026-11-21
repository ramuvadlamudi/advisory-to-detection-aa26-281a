# Deployment checklist

Before a detection is enabled in production:

- [ ] Unique ID and name (for example AA26-D05) and a one-line behaviour statement
- [ ] ATT&CK techniques and the advisory section it comes from
- [ ] Data sources confirmed present, with the fields populated (fieldsummary) and retention known
- [ ] Logic reviewed by a second engineer; uses CIM fields where possible
- [ ] Positive, negative and gap tests run and recorded
- [ ] False-positive conditions documented; exceptions held in a lookup with owner and review date
- [ ] Severity and risk score set; risk written to the right entity (user, system, or both)
- [ ] Schedule and search window set so consecutive runs neither overlap nor leave gaps; suppression where a baseline repeats
- [ ] Owner named (a team, not a person who might leave)
- [ ] Response instructions written: what the analyst checks first, and who approves containment
- [ ] Review date set (quarterly for behaviours; at expiry for indicators)
- [ ] Stored as code (YAML plus SPL) in version control; changes go through review
- [ ] Added to the readiness calculator; coverage and maturity updated
- [ ] After go-live: watch the first two weeks' volume, then record whether it found anything real ("operationally effective")
