# bh-vault-verify

Source of the Solana program `bh_vault` (Bloodhound Manual LP Terminal, milestone M2.11), published **only so that
anyone can rebuild it and check that the deployed program matches this source**. See `LICENSE`: source available for
verification only, all other rights reserved.

| | |
|---|---|
| Program id (Solana **devnet**) | `8vmMdR5ibh7Er3QUENpvfX8u8vfUssCezzec6EjZnNtu` |
| Source | this repository = commit `eb915ae343639c14c6132d7d3233c4d6deea709e` of the private development repo, path `terminal/program` (`Cargo.toml`, `Cargo.lock`, `programs/**`), byte-identical |
| Build image | `solanafoundation/solana-verifiable-build@sha256:be938e50e28b59de0ad7ec1bd3037f8c1720f1db9591377b265990a15815679b` (solana-cli / cargo-build-sbf 3.0.14, platform-tools v1.51) |
| Expected `bh_vault.so` sha256 | `9532e1973b8575a86b392211f713bf597ed8dd8abc18218e74cbe244e85e458f` (665,136 bytes) |
| Expected `solana-verify` executable / program hash | `f9a5c29bff65e9349f6e2d5535a4a32064f680c01aa8bc8ea82c6adea15b4280` |

`programs/cpi_probe` and `programs/pyth_mock` are test-only workspace members; they are kept so the workspace (and the
binary) is exactly what was deployed.

## Verify

With [solana-verify](https://github.com/Ellipsis-Labs/solana-verifiable-build) 0.5.2 and Docker, on Linux or WSL:

```sh
git clone https://github.com/gangsofthemeta/bh-vault-verify && cd bh-vault-verify
solana-verify build --library-name bh_vault \
  --base-image solanafoundation/solana-verifiable-build@sha256:be938e50e28b59de0ad7ec1bd3037f8c1720f1db9591377b265990a15815679b \
  "$PWD"
sha256sum target/deploy/bh_vault.so                      # 9532e197...
solana-verify get-executable-hash target/deploy/bh_vault.so    # f9a5c29b...
solana-verify get-program-hash -u https://api.devnet.solana.com 8vmMdR5ibh7Er3QUENpvfX8u8vfUssCezzec6EjZnNtu   # f9a5c29b...
```

or in one step: `solana-verify verify-from-repo -u https://api.devnet.solana.com --program-id
8vmMdR5ibh7Er3QUENpvfX8u8vfUssCezzec6EjZnNtu https://github.com/gangsofthemeta/bh-vault-verify --library-name bh_vault
--base-image <image above>`.

Notes: pass an absolute path to `solana-verify build` (a path of `.` is mis-handled by 0.5.2); do not add
`-- --locked` (the tool already passes it). `.gitattributes` turns off line-ending conversion so a Windows clone builds
the same bytes. Verification shows the binary matches this source; it is not an audit.

Security issues: report privately to support@gotmlabz.io.
