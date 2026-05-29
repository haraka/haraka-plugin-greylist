# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/).

### Unreleased

- test: refactored against test-fixtures 1.7.0

### [1.2.1] - 2026-05-24

- fix(security): escape `:` and `%` in tuple components
- fix: `load_config_lists` tolerates missing sections
- deps: bump versions

### [1.2.0] - 2026-05-20

- dep(address-rfc2822): upgrade to @haraka/email-address
- dep(all): bump versions to latest

### [1.1.2] - 2026-05-17

- fix: update redis calls for v4+ syntax
- tests: add a bunch

### [1.1.1] - 2026-03-31

- deps: bump versions
- ci: update configs
- test: remove unecessary done callbacks (#5)

### [1.1.0] - 2026-02-20

- deps: bump all versions to latest
- chore: refactor with es6 features
- remove void returns
- Fix TypeError by removing negation operator from remote.host usage
- chore: add GHA permissions for NPM publish
- dep(test-fixtures): allow newer versions

### [1.0.1] - 2025-01-30

- doc(CONTRIBUTORS): added
- style: move prettier config into package.json
- deps: bump to latest
- dep(eslint): upgrade to v9

### 1.0.0 - 2024-05-07

- initial NPM release

[1.0.1]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.0.1
[1.0.0]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.0.0
[1.1.0]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.1.0
[1.1.1]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.1.1
[1.1.2]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.1.2
[1.2.0]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.2.0
[1.2.1]: https://github.com/haraka/haraka-plugin-greylist/releases/tag/v1.2.1
