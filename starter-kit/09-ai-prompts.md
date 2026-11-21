# AI prompts for the advisory-to-detection workflow

AI drafts; people validate. Label everything AI produced, and test it against real data before it becomes a detection.

## Stage 1: give AI the advisory

> From this advisory, list each adversary behaviour as one sentence. For each, give the ATT&CK technique, the telemetry and fields
> that would record it, and one testable hypothesis in the form "A [entity] that [evidence], [in context], may indicate [behaviour]."
> Quote the advisory text that supports each behaviour. Say "not stated" rather than guessing.

Check: every behaviour has a quote; no claims the advisory doesn't make (AA26-281A does not attribute AI use).

## Stage 2: connect it to the SIEM

> Using only searches you run, list the indexes, sourcetypes and retention available, and the populated fields in each source
> relevant to these hypotheses. Then write SPL for hypothesis N using only field names you have seen in the results.

Check: run the SPL yourself. Zero results can mean "no attack" or "wrong fields": test it on known-bad data first.

## Stage 3: challenge it

> Which of these behaviours can this environment not detect, and why? For each, name the missing telemetry or configuration,
> the fix, and how we would test the fix.

Check: compare each claim with a search result. In the lab, a typical first draft assumed `src_ip` and `action=failure`; the IIS
data has `c_ip`, and `action` is only `allowed` or `blocked`, so the draft returned nothing. `fieldsummary` and
`stats count by action` would have shown both in seconds.

## Five questions every AI finding must answer

1. What evidence supports it?
2. Which fields and behaviours contributed?
3. How confident is it, and why?
4. What evidence is missing?
5. What should the analyst do next?
