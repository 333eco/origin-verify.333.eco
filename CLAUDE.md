# CLAUDE.md — origin-verify.333.eco

`@333eco/origin-verify` — public, CC0. ⛔ No runtime dependencies, and no Node modules or `Buffer` outside `cli.mjs` and `test/`: it runs on the browser floors (iOS 17, Chrome 113; `test/make-browser-selftest.mjs`). ⛔ `pixels` and `phash` are permanent once in the log: a change is a new field. ⚠️ It shares no code with the service on purpose. Doctrine is canonical in memory (`project_b_origin`); spec: the private `sign.333.eco` SPEC.md §9. Memory wins.

- ⛔ **The suite's value is its refusals.** Every guard has a CONTROL test that is seen to fail. Mutation-test with an apply check: on 2026-11-03, 14 of 45 mutations survived a green suite.
- ⛔ This repo is public: no customer names, no private spec text.
- Publish = bump `version` on main; CI gates on the tests and needs the `NPM_TOKEN` repo secret. Verify with `npm view`.
