# CLAUDE.md

Context for AI coding assistants (Claude, Cursor, Copilot, etc.) working in this repo.

## What this is

MCP server that connects Google Search Console to AI assistants.
Single file: `gsc_server.py` (~1,670 lines). Built with FastMCP — no custom framework.

## Running locally

```bash
uv sync
uv run python gsc_server.py
```

## Auth

Two modes, tried in order:

1. **OAuth (default):** Place `client_secrets.json` in the repo root. On first run, a browser window opens for Google login. Token saved to `token.json` (gitignored), auto-refreshes when expired.
2. **Service account:** Set `GSC_CREDENTIALS_PATH` to the path of your service account JSON key file.

Set `GSC_SKIP_OAUTH=true` to force service account mode and skip OAuth entirely.

## Key environment variables

| Variable | Default | Description |
|---|---|---|
| `MCP_TRANSPORT` | `stdio` | `stdio` or `streamable-http` (shared, stateless, read-only). `sse` is gone; other values raise `ValueError` |
| `MCP_HOST` | `127.0.0.1` | Host to bind when `MCP_TRANSPORT=streamable-http` |
| `MCP_PORT` | `3001` | Port to bind when `MCP_TRANSPORT=streamable-http`; also the port in the allowed `Host` values |
| `GSC_DATA_STATE` | `all` | `all` = matches GSC dashboard; `final` = confirmed data only (2–3 day lag) |
| `GSC_ALLOW_DESTRUCTIVE` | `false` | Set `true` to enable `add_site`, `delete_site`, `delete_sitemap` |
| `GSC_CREDENTIALS_PATH` | — | Path to service account JSON key file |
| `GSC_OAUTH_CLIENT_SECRETS_FILE` | `client_secrets.json` | Path to OAuth client secrets file |
| `GSC_SKIP_OAUTH` | `false` | Set `true` to skip OAuth and use service account only |

## streamable-http mode

`configure_streamable_http()` sets host, port, `stateless_http=True` and `TransportSecuritySettings` (allowed hosts exactly `127.0.0.1:<port>` and `localhost:<port>`, no allowed origins), then unregisters every tool not in `READ_ONLY_TOOLS`. stdio keeps all 22 tools (destructive ones still behind `GSC_ALLOW_DESTRUCTIVE`). Read-only over HTTP: `list_properties`, `get_search_analytics`, `get_site_details`, `get_sitemaps`, `inspect_url_enhanced`, `batch_url_inspection`, `check_indexing_issues`, `get_performance_overview`, `get_advanced_search_analytics`, `compare_search_periods`, `get_search_by_page_query`, `list_sitemaps_enhanced`, `get_sitemap_details`, `get_creator_info`.

## Token handling

`get_oauth_credentials()` never deletes `token.json`. Read, refresh and write run under an `fcntl` lock on `token.json.lock` (`_token_lock()`), with the token re-read inside the lock; writes go through `_write_token_atomic()` (temp file in the same dir, `0600`, `os.replace`). An unusable token without a TTY raises `TokenError` naming the file and the cause. `reauthenticate` writes only after a successful login.

## Adding a new tool

1. Add a **synchronous** function decorated with `@mcp.tool()` and then `@_run_in_worker` (in that order). The decorator runs the whole body in `asyncio.to_thread`, so blocking Google calls never stall the event loop
2. Classify it: add the name to `READ_ONLY_TOOLS` only if it cannot change anything in Search Console or on disk. `test_every_registered_tool_is_classified` fails until you also update the test's tool sets
3. Use `get_gsc_service()` for auth — it handles OAuth and service account automatically
4. Return `json.dumps(result)` not formatted text strings (LLMs work better with structured data)
5. Handle `HttpError` and return a plain string error message on failure
6. To call another tool from inside a tool, use its sync body: `other_tool.__wrapped__(...)`

```python
@mcp.tool()
@_run_in_worker
def my_new_tool(site_url: str) -> str:
    """One-line description shown to the AI as the tool's purpose."""
    try:
        service = get_gsc_service()
        result = service.someApi().someMethod(siteUrl=site_url).execute()
        return json.dumps(result)
    except Exception as e:
        if "404" in str(e):
            return _site_not_found_error(site_url)
        return f"Error: {str(e)}"
```

## Running tests

```bash
uv run --with pytest pytest test_gsc_server.py -v
```

No credentials needed — all Google API calls are mocked with `unittest.mock`. Set `GSC_CONFIG_DIR` to a scratch directory when running the suite on a machine with a real token: a few older tests load the module without their own config dir.

## Docker

```bash
docker build -t mcp-gsc .
docker run -e MCP_TRANSPORT=streamable-http -e MCP_HOST=0.0.0.0 -e MCP_PORT=3001 \
  -v /path/to/client_secrets.json:/app/client_secrets.json \
  -p 3001:3001 mcp-gsc
```
