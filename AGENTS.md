# Notes for coding agents

- Read `README.md` for the model and `docs/reference.md` for every reason code and error code.
  Both ship with the package and match its version.
- Public API: `src/index.ts` (core) and `src/testing/index.ts` (`permitkit/testing`). Nothing else
  is public.
- The decision functions are pure. Pass `context.now`; never add a clock read, randomness or I/O to
  `src/decide.ts`, `src/approval.ts` or `src/engine/`.
- Every security rule has a test. If you change a rule, run the suite with the rule turned off
  once and confirm that the named test fails, then restore it.
- Gates: `pnpm check` runs typecheck, lint, format check, tests, build, the smoke tests, the
  bundle check, the consumer types check and the pack check. The second smoke test scans `dist`
  for plain uses of Node built-ins and runs it in a V8 context without them. The scan is a
  tripwire, not a proof: it cannot see names built at run time, so never compute a global or
  module name in `src`.
- Releases: a tag `vX.Y.Z` on `main` starts `.github/workflows/release.yml`, which publishes to
  npm through trusted publishing. Except for the one-time manual 0.1.0, never publish from a
  local machine, and never add an npm token to the repository. Steps: `docs/releasing.md` in the
  repository.
- Every input uses hand-written validators (`src/validate.ts`, `src/request.ts`,
  `src/policy-document.ts`, `src/approval-input.ts`, `src/record.ts`). permitkit has no runtime
  dependency; do not add one. `pnpm bundle-check` fails if `package.json` lists one or if the
  bundle of all exports holds a module outside `dist`.
- The validators follow the Zod 3 schemas of f04df14. `test/zod-verdicts.test.ts` compares them
  with the recorded Zod verdicts in `test/zod-verdicts/`, which cannot be recorded again: do not
  change the generators, seeds or run counts in `test/verdict-corpora.ts` and the modules it
  uses. A validator never changes its input, and calls only built-ins captured in
  `src/intrinsics.ts`; `test/call-time-spy.test.ts` checks that.
- Absence never widens access. Never add a schema default or an optional field whose absence
  means "everywhere", "no limit" or "no deny rules"; the wide case is an explicit `kind` value. See
  "Design choices" in `README.md`.
