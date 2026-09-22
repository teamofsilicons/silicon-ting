# CLI updates

Verified on 22 September 2026. Existing account credentials were preserved. CLI packages were updated through their package manager or checksum-verified official release.

| Homebrew CLI/tool | Active version |
| --- | --- |
| awscli | 2.36.50 |
| bash | 5.3.20 |
| cloudflared | 2026.9.1 |
| cocoapods | 1.17.0 |
| coreutils | 9.12 |
| doctl | 1.169.0 |
| emacs | 31.1_1 |
| exiftool | 13.55_1 |
| fnm | 1.39.0 |
| gh | 2.101.0 |
| gnupg | 2.5.22 |
| htop | 3.5.3 |
| imagemagick | 7.1.2-31 |
| mcp-publisher | 1.8.1 |
| mole | 1.55.0 |
| openai-whisper | 20250625_6 |
| opencode | 1.18.30_2 |
| openjdk | 27 |
| parallel | 20260822 |
| pipx | 1.17.5 |
| pnpm | 12.5.1 |
| poppler | 26.09.0 |
| protobuf | 36.2 |
| pyenv | 2.8.6 |
| python@3.13 | 3.13.15 |
| python@3.9 | 3.9.25 |
| rclone | 1.75.1 |
| ripgrep | 15.2.0 |
| summarize | 0.22.0 |
| swig | 4.5.1 |
| tree | 2.3.2 |
| uv | 0.12.17 |
| xcodegen | 2.46.0 |
| yt-dlp | 2026.8.19_1 |
| zig | 0.16.0_1 |

| npm global package | Version |
| --- | --- |
| @earendil-works/pi-coding-agent | 0.87.0 |
| @helgesverre/namecheap-cli | 0.1.0 |
| @tiny-fish/cli | 0.46.1 |
| agent-browser | 0.38.1 |
| claudish | 10.0.1 |
| openclaw | 2026.9.5 |

| Additional executable | Version |
| --- | --- |
| IAM | 3.1.0 |
| Honeycomb | 0.3.0 |
| Space Station | 0.1.4 |
| Briefcase | 1.1.1 |
| NATS CLI | 0.5.0 |
| Node.js | 26.9.0 |
| npm | 12.0.2 |
| Ting CLI and daemon | 0.1.0 |
| LiveKit CLI | 2.18.7 |

The two pipx packages were also upgraded: `silicon-cli` 1.0.11 → 1.0.61 and `silicon-browser` 0.1.1 → 1.1.1. The separate effective `silicon` executable reports 4.0.9; `silicon-browser` reports 1.1.1.

Rust stable 1.98.1, rustup 1.29.1, cargo-xwin 0.23.1 and cargo-zigbuild 0.23.4 were already current. No uv-managed tools were installed. The final npm global outdated check returned no packages.

The effective Node/npm/npx launchers now use the current runtime and npm prefix `~/.local`; their previous launchers were saved with `.pre-ting-update` suffixes. Official-release replacements also have backups. Homebrew may retain older kegs, and Cargo install receipts may still describe the original package after an official binary replacement; the executable versions above are authoritative.

This update covers CLI tools and their required runtimes. Database/server services, macOS-provided tools and Xcode were not upgraded as CLI packages. NATS was installed from its verified official binary because the Homebrew source build required newer Xcode.
