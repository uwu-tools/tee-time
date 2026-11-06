# tee-time

Run [OpenSSF Scorecard](https://github.com/ossf/scorecard) once, and let
[AMPEL](https://github.com/policylabs/ampel) decide.

Scorecard writes its in-toto result. AMPEL evaluates that saved result
against a policy, offline and with no repository token, and sets the exit
code. Neither tool needs a change.

## Run it

```sh
go install github.com/ossf/scorecard/v5@v5.6.0
go install github.com/policylabs/ampel/cmd/ampel@v1.5.0
go install github.com/carabiner-dev/bnd@v0.4.7
GITHUB_AUTH_TOKEN=<token> ./scorecard-ampel.sh
```

The script scans `ossf/scorecard` and `ossf/allstar`, runs AMPEL's
[Scorecard policies](https://github.com/carabiner-dev/policies/tree/main/scorecard)
against the results, and checks each exit status. It exits with the
number of cases that didn't match.

## Cases

- `pass-sast`: SAST scores 10; the policy passes.
- `advisory-token-perms`: Token-Permissions scores 9. The policy is
  advisory (`enforce: "OFF"`), so AMPEL reports it and exits 0.
- `fail-token-perms`: the same policy, enforced, exits 1.
- `fail-code-review`: Code-Review scores 1 on `ossf/allstar`; exit 1.
- `wrong-subject`: one repo's evidence checked against another repo's
  commit exits 1.
- `missing-check`: **expected to fail, but passes.** A scan that never ran
  SAST passes the SAST policy
  ([carabiner-dev/policies#46](https://github.com/carabiner-dev/policies/issues/46)).
- `missing-check-fixed`, `pass-sast-fixed`: requiring the check to be
  present fixes it.

The last four cases sign the `ossf/scorecard` evidence with a throwaway
key (`keygen.go`, signed with `bnd`) and check it with a policy that
requires a verified signature:

- `signed`: verified with the signer's public key; exit 0.
- `signed-wrong-key`: verified with a different key; exit 1.
- `unsigned`: the raw statement; exit 1.
- `signed-wrong-key-not-required`: the upstream policy passes even with
  the wrong key. AMPEL admits evidence passed with `-a` whatever its
  signature, so the policy has to require one.

Until #46 is resolved, the script exits 1. It exits 2 if a tool is
missing or Scorecard returns no result.
