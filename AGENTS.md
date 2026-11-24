# Notes for coding agents

- Read `README.md` for the model and `docs/reference.md` for every reason code and error code.
  Both ship with the package and match its version.
- Public API: `src/index.ts` (core) and `src/testing/index.ts` (`permitkit/testing`). Nothing else
  is public.
- The decision functions are pure. Pass `context.now`; never add a clock read, randomness or I/O to
  `src/decide.ts`, `src/approval.ts` or `src/engine/`.
- Every security rule has a test. If you change a rule, run the suite with the rule turned off
  once and confirm that the named test fails, then restore it.
- Gates: `pnpm check` runs typecheck, lint, format check, tests, build, the smoke tests and the
  bundle check. The second smoke test scans `dist` for plain uses of Node built-ins and runs it in
  a V8 context without them. The scan is a tripwire, not a proof: it cannot see names built at
  run time, so never compute a global or module name in `src`.
- Requests and policy documents use hand-written validators (`src/validate.ts`,
  `src/request.ts`, `src/policy-document.ts`). Zod 3 is still a runtime dependency, but only
  approval inputs (through `src/zod-schemas.ts`) and decision records (`src/audit.ts`) use it,
  until their own validators replace it. Do not import Zod anywhere else, and do not add a
  runtime dependency.
  `pnpm bundle-check` fails if `decide` pulls in Zod.
- Absence never widens access. Never add a schema default or an optional field whose absence
  means "everywhere", "no limit" or "no deny rules"; the wide case is an explicit `kind` value. See
  "Design choices" in `README.md`.
