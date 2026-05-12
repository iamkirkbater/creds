# creds

A CLI tool for authenticating to AWS using Red Hat's SAML IDP, designed to integrate with the native AWS credential chain via [`credential_process`](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html).

This project is heavily inspired by [rh-aws-saml-login](https://github.com/app-sre/rh-aws-saml-login). It serves the same core purpose — authenticating via Red Hat's Kerberos/SAML flow to obtain temporary AWS credentials — but takes a different approach to how those credentials are consumed. Between my personal usage of AWS Profiles on my current project as well as problems I was having with the python environment, I decided to create this tool to provide a simpler, more native solution.

If you need to launch a web browser for a given AWS Account, use the `rh-aws-saml-login` CLI tool instead.

## Why not rh-aws-saml-login?

`rh-aws-saml-login` spawns a subshell with `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` exported as environment variables. This works, but has some drawbacks:

- You're working inside a subshell with a ~1 hour window before credentials expire.
- You need to re-run the tool and get a new shell when they do.
- You can't use named AWS profiles, so switching between accounts means exiting and re-entering shells.

`creds` instead acts as an [external credential process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) for the AWS CLI. You configure it once in `~/.aws/config` and then use standard `AWS_PROFILE` to switch between accounts. The AWS SDK handles calling `creds` automatically whenever it needs fresh credentials, and `creds` caches them locally so you're not re-authenticating on every CLI call. Everything is still short-lived STS tokens under the hood.

## Installation

```bash
go install github.com/iamkirkbater/creds@latest
```

Or build from source:

```bash
go build -o creds .
```

## Prerequisites

- A valid Kerberos configuration (`/etc/krb5.conf`) for the Red Hat realm
- VPN access to Red Hat's internal network
- `kinit` available on your `$PATH`

## Usage

### Setting up AWS profiles

Add entries to your `~/.aws/config` for each account/role you need:

```ini
[profile my-account]
credential_process = /path/to/creds auth --account 123456789012 --role MyRoleName
region = us-east-1

[profile other-account]
credential_process = /path/to/creds auth --account 987654321098 --role OtherRole --region eu-west-1
```

### Using it

Once configured, just use AWS as normal:

```bash
# Uses the profile's credential_process automatically
AWS_PROFILE=my-account aws s3 ls

# Or with the --profile flag
aws sts get-caller-identity --profile my-account
```

The first call will trigger Kerberos/SAML authentication (prompting for your password via `kinit` if needed). Subsequent calls use cached credentials until they're within 5 minutes of expiration.

### Direct invocation

You can also run it directly to see the credential JSON:

```bash
creds auth --account 123456789012 --role MyRoleName
```

Output follows the [credential_process](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-sourcing-external.html) JSON contract:

```json
{
  "Version": 1,
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "SessionToken": "...",
  "Expiration": "2026-05-12T17:00:00Z"
}
```

### Flags

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--account` | yes | | AWS account ID |
| `--role` | yes | | IAM role name to assume |
| `--region` | no | `us-east-1` | AWS region |
| `--duration` | no | `3600` | Session duration in seconds |

## How it works

1. Checks the local cache (`~/.aws/cli/cache/`) for valid credentials with >5 minutes remaining.
2. If no cache hit, ensures a valid Kerberos ticket exists (runs `kinit` interactively if needed).
3. Authenticates to Red Hat's SAML IDP using SPNEGO/Kerberos.
4. Validates the requested role is available in the SAML assertion.
5. Calls AWS STS `AssumeRoleWithSAML` to get temporary credentials.
6. Caches the credentials locally and outputs them in `credential_process` format.

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE) for details.
