# Contributing

Thanks for your interest!

- Report ordinary bugs or suggest features through GitHub issues.
- Report security/privacy issues privately using [SECURITY.md](SECURITY.md).
- Fork, branch and open a pull request for a change.

## Development

Use the pinned tools and commands in [README.md](README.md). Before opening a pull request, run the same checks as CI:

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
npm ci
npm run check
npm run test:crypto
npm test
```

Behavioral/security changes need meaningful regression coverage. Never use real account tokens, private keys or forum content as fixtures. Keep authentication, member authorization, publisher approval, validator consensus and archive storage permissions separate. The product's trust boundaries and current limitations live in [ARCHITECTURE.md](ARCHITECTURE.md).

## Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin 1.1](https://developercertificate.org/). Sign off commits using `git commit -s` to certify you have the right to submit the change under MIT. Do not copy a runtime member's anonymous identity into Git metadata; repository contribution identity is a separate choice.

## Review and release notes

Describe user impact, actions and limitations. Do not claim that tests establish anonymity, that hash linking alone establishes consensus, or that independent agent review constitutes a professional security audit. Keep the master architecture and [audit ledger](docs/AUDIT.md) accurate as changes land.

## License

MIT. See [LICENSE](LICENSE).
