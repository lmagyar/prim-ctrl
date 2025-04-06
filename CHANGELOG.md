# Changelog

## 0.7.12

- Increase test timeout and add log waiting for external (funnel) tailscale accessibility

## 0.7.11

- Increase test timeout for external (funnel) tailscale accessibility

## 0.7.10

- Fix finding device on Tailscale API

## 0.7.9

- Increase timeout for Tailscale API

## 0.7.8

- Increase wait time after fresh new local Tailscale startup

## 0.7.7

- Increase test timeout for external (funnel) tailscale accessibility

## 0.7.6

- Increase test timeout for local tailscale accessibility

## 0.7.5

- Add note to exception if Tailscale is not installed properly

## 0.7.4

- Refactor exception logging arguments

## 0.7.3

- Simplify source account check in flow
- Use Git LFS for *.png

## 0.7.2

- Extend flow with different managing accounts than the phone's account

## 0.7.1

- Fix disconnect error during stopping pftpd
- Fix error handling during error handling

## 0.7.0

- Specify private SSH key for authentication (new keyfile option)
- Authenticate SFTP server's SSH keys to avoid using outdated cached zeroconf addresses
- Test Funnel's external access after DNS configuration test
- Refactor Subprocess
- Do not catch keyboard exceptions

## 0.6.5

- Delay Funnel's DNS configuration test (new secretfile sub-option)
- Refactor caching, logging

## 0.6.4

- Fix starting local Tailscale

## 0.6.3

- Fix local webhook test

## 0.6.2

- Test Funnel's DNS configuration
- Update dependencies

## 0.6.1

- Stop local Tailscale on error
- Fix wait for local Tailscale
- Refactor exception logging

## 0.6.0

- Start/stop local Tailscale also

## 0.5.0

- Update Python installation in Readme
- Mention in the error message to check that the Automate flow is running
- Do not mention my forked prim-ftpd, PR-s got merged in the original repo
- Update dependencies

## 0.4.0

- Update dependencies

## 0.3.0

- Publish on PyPI
- Use python-poetry

## 0.2.0

- Update dependencies

## 0.1.0

- Initial upload
