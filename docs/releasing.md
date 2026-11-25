# Releasing

The workflow `.github/workflows/release.yml` publishes permitkit to npm. Nobody publishes from a
local machine, and the repository holds no npm token.

## Make a release

1. On a branch, set `version` in `package.json` to the new version, for example `0.2.0`. Change
   the version in the install command in `README.md` too.
2. Merge the change to `main` after CI passes.
3. Tag the commit on `main` that holds the new version, and push the tag:

   ```sh
   git switch main && git pull --ff-only
   git tag -a v0.2.0 -m "permitkit 0.2.0"
   git push origin v0.2.0
   ```

4. The workflow starts on the tag. It stops if the tagged commit is not on `main` or if the tag is
   not `v` plus the `package.json` version. It runs `pnpm check`, packs the tarball, runs the
   smoke test on Node 22.3.0 and waits for approval in the GitHub environment `npm`. After
   approval it publishes the tarball with provenance.
5. Check the release with `npm view permitkit@0.2.0` and `npm audit signatures` in a project that
   installs it.

Only tags of the form `vX.Y.Z` start the workflow. A pre-release tag such as `v1.0.0-rc.1` does
not. A published version cannot be replaced. If a release is wrong, publish a new patch version.

## One-time setup

### GitHub

- Make the repository public before the first release. npm creates provenance only for packages
  built in a public repository.
- Settings, Environments: create the environment `npm` before the first tag. Add a required
  reviewer, and limit it to tags that match `v*.*.*`. If the environment does not exist, GitHub
  creates it on the first run without protection rules, and the publish job runs without
  approval.
- Settings, Rules: add a tag ruleset for `v*` that lets only maintainers create, update or delete
  release tags. GitHub runs the `release.yml` of the tagged commit, so a tag on a commit with a
  changed workflow could skip the checks. npm checks only the repository, the workflow file name
  and the environment, not the commit. The reviewer of the `npm` environment confirms that the
  run is for a tag on `main`.
- In the security section of the repository settings, turn on private vulnerability reporting
  (see `SECURITY.md`).

### npm

On npmjs.com, open the package `permitkit`, Settings, Trusted publishing, and add a GitHub Actions
publisher:

| Field                | Value          |
| -------------------- | -------------- |
| Organization or user | `dectria-GmbH` |
| Repository           | `permitkit`    |
| Workflow filename    | `release.yml`  |
| Environment name     | `npm`          |

All fields are case-sensitive, and npm does not check them when you save. A new trusted publisher
expires if no publish succeeds through it within 2 days, so add it shortly before the first tag.
Under allowed actions, allow `npm publish`. A new trusted publisher allows only
`npm stage publish` by default, and the workflow runs `npm publish`.

After the first release through the workflow, set Settings, Publishing access to "Require
two-factor authentication and disallow tokens". Trusted publishing keeps working, because it does
not use a token.

Trusted publishing needs npm 11.5.1 or newer and Node 22.14.0 or newer on the runner. The workflow
uses Node 24 and fails if its npm is older. Reference: https://docs.npmjs.com/trusted-publishers
