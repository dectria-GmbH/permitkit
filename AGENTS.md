# Notes for coding agents

- Read `README.md` for the model and `docs/reference.md` for every reason code and error code.
  Both ship with the package and match its version.
- Public API: `src/index.ts` (core) and `src/testing/index.ts` (`permitkit/testing`). Nothing else
  is public.
- The decision functions are pure. Pass `context.now`; never add a clock read, randomness or I/O to
  `src/decide.ts`, `src/approval.ts` or `src/engine/`.
- Every security rule has a test. If you change a rule, run the suite with the rule turned off
  once and confirm that the named test fails, then restore it.
- Gates: `pnpm check` runs typecheck, lint, format check, tests, build and the smoke tests. The
  second smoke test scans `dist` for plain uses of Node built-ins and runs it in a V8 context
  without them. The scan is a tripwire, not a proof: it cannot see names built at run time, so
  never compute a global or module name in `src`.
- The only runtime dependency is Zod 3. Do not add another one.
- Absence never widens access. Never add a schema default or an optional field whose absence
  means "everywhere", "no limit" or "no deny rules"; the wide case is an explicit `kind` value. See
  "Design choices" in `README.md`.
