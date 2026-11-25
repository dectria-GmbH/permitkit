# Security policy

## Report a vulnerability

Use GitHub private vulnerability reporting. Open the "Security" tab of
https://github.com/dectria-GmbH/permitkit and choose "Report a vulnerability".

Do not open a public issue or pull request for a vulnerability.

## Supported versions

Only the latest released 0.x version receives security fixes.

## Scope

permitkit is a library for authorization decisions. A report is in scope if it shows a way to get
`allow` where the policy and the request call for `deny`, to bypass dual approval, separation of
duties or the limits of an agent grant, to make a decision function throw or hang on hostile
input, or to make a decision record replay to a different result under the same policy version.
