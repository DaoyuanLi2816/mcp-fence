# Changelog

All notable changes to this project will be documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

Tracked in-repo as `0.1.2`; not yet published to PyPI.

### Added
- Source-code scan rules `MCPG036`-`MCPG040`: shell invocation
  (`shell=True`, `os.system`, `os.popen`), use of `eval()`/`exec()`, unsafe
  deserialization (`pickle.loads`, `yaml.load` without `SafeLoader`),
  disabled TLS verification (`verify=False`), and hard-coded secrets in
  source. The rule catalog now covers `MCPG001`-`MCPG040`.

### Fixed
- `init-example` now finds the bundled examples after a plain `pip install
  mcp-fence`. They previously only existed inside a git checkout, so the
  documented quickstart failed at step 1 on a clean install.
- The bundled example `mcp.json` files pointed their server `args` at
  `examples/...`, a path that only resolves inside a git checkout. They now
  point at `mcp-fence-examples/...`, matching what `init-example` actually
  produces, so `inspect`/`fuzz`/`sandbox` against the bundled examples work
  from a fresh directory.
- The shipped `.github/workflows/mcp-fence.yml` action now merges every
  discovered config into a single SARIF run (GitHub rejects more than one
  run per category) and installs the published package instead of an
  editable checkout.
- `code_scan` no longer flags `eval(`/`exec(` inside comments, string
  literals, or method calls like `model.eval()`.
- `config_scan` no longer double-counts `MCPG033`/`MCPG034`/`MCPG021`
  findings.
- `ScanResult.tool_version` and the MCP client handshake version now read
  from `mcp_fence.__version__` instead of a hard-coded `"0.1.0"`.

### Changed
- README and docs now point every bundled-example command at the
  `init-example` destination (`mcp-fence-examples/...`) instead of a
  repo-only `examples/...` path.

## [0.1.1] - 2026-06-10

### Changed
- README masthead: SVG hero banner (also rendered on the PyPI project page)
  and centered badges; architecture diagram switched to an absolute URL so it
  renders on PyPI.
- Releases now publish to PyPI via trusted publishing (`release.yml`) on
  GitHub release. No code changes.

## [0.1.0] - 2026-05-16

### Added
- `mcp-fence scan` — static scanning of MCP server configs, startup commands,
  tool metadata, JSON schemas, and project directories. Outputs `text`, `json`,
  `sarif`, and `html`.
- `mcp-fence inspect` — minimal stdio MCP client that runs `initialize`,
  `initialized`, and `tools/list` against a server, captures stderr, and
  reports an inventory.
- `mcp-fence fuzz` — schema-driven dynamic fuzzer covering path traversal,
  command injection, SSRF, prompt injection, oversize input, type confusion,
  and secret probing. Safe-mode by default; `--toy-mode` for `examples/` and
  `--allow-unsafe` for advanced users.
- `mcp-fence sandbox` — Docker run command builder with `strict`,
  `filesystem-readonly`, `network-deny`, and `dev` profiles. `--dry-run`
  works without Docker installed.
- `mcp-fence report` — generates standalone offline HTML reports and
  SARIF 2.1.0 for GitHub code scanning.
- `mcp-fence init-example` — copies the bundled example servers into the
  user's working directory.
- Bundled example servers: `safe_server`, `vulnerable_filesystem_server`,
  `vulnerable_shell_server`, `vulnerable_metadata_server`,
  `vulnerable_http_server` (config-only).
- Optional local-LLM semantic judge (`--llm-judge ollama`) targeting Ollama
  or any OpenAI-compatible local endpoint. Disabled by default.
- 35 rules (`MCPG001`–`MCPG035`) covering startup commands, tool poisoning,
  schema risks, dynamic behavior, and sandbox recommendations.
- GitHub Actions CI workflow and reusable `mcp-fence.yml` action snippet.
- Documentation: `threat_model.md`, `rule_catalog.md`, `sandboxing.md`,
  `local_llm.md`, `methodology.md`, `roadmap.md`.

### Known limitations
- Streamable HTTP / SSE transport: detection lives in `config_scan`;
  live HTTP inspection is **experimental** and tracked in
  `docs/roadmap.md`.
- Docker execution on Windows is best-effort; `--dry-run` is the supported
  path on Windows runners.
