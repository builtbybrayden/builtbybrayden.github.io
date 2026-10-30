---
title: 'Unauthenticated by Default: Four Findings in PrivateGPT 0.6.2'
description: 'PrivateGPT 0.6.2 ships with API authentication turned off on a server listening on every interface, plus unbounded upload and query parameters that make denial of service a one-line curl. Reported in April 2026, with no response from the vendor.'
pubDate: '2026-10-30'
---

## The short version

PrivateGPT is one of the best-known open source projects for chatting with your own documents using local language models. It has more than 57,000 stars on GitHub. Its whole pitch is privacy: your documents stay on your machine.

In April 2026 I reviewed version 0.6.2, the last release of the original line, and found four issues. Three of them matter:

- **The API has no authentication out of the box.** The shipped configuration turns auth off, and the default launcher listens on every network interface. Anyone who can reach port 8001 can list, read, poison or delete the document collection.
- **The ingest endpoints accept uploads of any size.** The full body is loaded into memory, written to disk and run through the embedding pipeline with no size check.
- **The `/v1/chunks` search endpoint takes an unbounded result count**, plus an unbounded "neighboring chunks" multiplier, so one request can force an arbitrarily expensive vector search.

I reported these privately on April 28, followed up by email several times between July and September, and resubmitted them as GitHub security advisories on August 24 once the repository supported private reporting. As of October 30 I have not received any response. The 90-day window I gave ended in July, so I'm publishing the details and requesting CVE IDs through VulDB. CVE numbers will be added here once they're assigned.

| ID | Finding | Weakness | CVSS 3.1 | CVE |
|---|---|---|---|---|
| PGPT-004 | API authentication disabled by default, server bound to 0.0.0.0 | CWE-306 / CWE-1188 | 9.8 | pending |
| PGPT-001 | No request size limit on ingest endpoints | CWE-400 | 7.5 | pending |
| PGPT-002 | Unbounded `limit` and `prev_next_chunks` on `/v1/chunks` | CWE-770 | 7.5 | pending |
| PGPT-003 | `file_name` stored without sanitization | CWE-20 | 4.3 | not requested |

## Some background

PrivateGPT is a FastAPI service wrapped around LlamaIndex. You upload documents through the ingest API, it splits them into chunks and embeds them into a vector store, and then you ask questions through chat and completion endpoints that pull the relevant chunks back out. The repository ships a `settings.yaml` with defaults, and you start the server with `python -m private_gpt`.

That default configuration is what everything below is measured against, because it is what a person following the quick start ends up running.

## PGPT-004: authentication is off, and the server is listening

Two defaults combine here.

First, `settings.yaml` ships with:

```yaml
server:
  port: ${PORT:8001}
  auth:
    enabled: false
```

When auth is disabled, `private_gpt/server/utils/auth.py` replaces the real authentication check with a stub when the module is imported:

```python
if not settings().server.auth.enabled:
    def authenticated() -> bool:
        """Check if the request is authenticated."""
        return True
```

Every route depends on `authenticated()`, so every route accepts every request.

Second, the launcher in `private_gpt/__main__.py` binds to all interfaces:

```python
uvicorn.run(app, host="0.0.0.0", port=settings().server.port, log_config=None)
```

The result: a stock install answers anyone on the network, with no credentials.

```bash
# Enumerate every ingested document
curl http://<host>:8001/v1/ingest/list

# Pull raw document content back out through semantic search
curl -X POST http://<host>:8001/v1/chunks -H "Content-Type: application/json" \
  -d '{"text":"password"}'

# Plant attacker-controlled content in the knowledge base
curl -X POST http://<host>:8001/v1/ingest/text -H "Content-Type: application/json" \
  -d '{"file_name":"evil.txt","text":"<attacker content>"}'

# Delete any document
curl -X DELETE http://<host>:8001/v1/ingest/<doc_id>
```

For a tool whose whole reason to exist is keeping documents private, this is the issue that matters most. The poisoning case is worth calling out on its own: anyone who can reach the API can quietly add "documents" that the model will later cite back to legitimate users as if they were part of the trusted corpus.

The same `settings.yaml` also enables CORS with `allow_origins: ["*"]`. That issue already has a CVE ([CVE-2025-4515](https://nvd.nist.gov/vuln/detail/CVE-2025-4515)) and I'm not claiming it here. It does make the missing authentication worse, though: a malicious web page opened by someone running PrivateGPT can drive the unauthenticated API from that person's browser, even when the service isn't exposed to the network.

**Fix:** Turn authentication on by default, or refuse to start when auth is off and the server is bound to a non-loopback address. Bind to `127.0.0.1` by default.

## PGPT-001: no limit on how much you can upload

`POST /v1/ingest/file` and `POST /v1/ingest/text` will accept a body of any size. Here's the path from the HTTP request to the embedding pipeline:

```
ingest_router.py:60     service.ingest_bin_data(file.filename, file.file)
ingest_service.py:82    file_data = raw_file_data.read()       # entire upload into RAM
ingest_service.py:60    path_to_tmp.write_bytes(file_data)     # written to disk
ingest_helper.py:96     reader_cls().load_data(file_data)      # full parse + embedding
```

Nothing along that path checks size, and the server never returns `413 Payload Too Large`. Memory, disk and embedding compute all grow with whatever the client sends.

```bash
dd if=/dev/urandom bs=1M count=10 | curl -X POST http://localhost:8001/v1/ingest/file \
  -F 'file=@-;filename=large.pdf;type=application/pdf'          # HTTP 200

curl -X POST http://localhost:8001/v1/ingest/text -H "Content-Type: application/json" \
  -d '{"file_name":"x.txt","text":"'$(python3 -c 'print("A"*5000000)')'"}'   # HTTP 200
```

PrivateGPT already has two upload-related DoS CVEs, and this is neither of them. CVE-2024-12063 is about an oversized *filename*, and CVE-2024-8018 is about an oversized *multipart boundary*. This one is about the request body: the service buffers, stores and embeds whatever it's given.

**Fix:** Add request-size middleware with a configurable maximum, add `max_length` to `IngestTextBody.text`, and stream uploads instead of buffering them whole.

## PGPT-002: ask for two billion results

`/v1/chunks` is the semantic search endpoint. Its request model looks like this:

```python
class ChunksBody(BaseModel):
    text: str = Field(examples=["Q3 2023 sales"])
    context_filter: ContextFilter | None = None
    limit: int = 10
    prev_next_chunks: int = Field(default=0, examples=[2])
```

Neither `limit` nor `prev_next_chunks` has an upper bound. `limit` goes straight into the retriever as `similarity_top_k`, and `prev_next_chunks` makes the service fetch that many neighboring chunks for *every* result. The cost of one request scales with the product of the two.

```bash
curl -X POST http://localhost:8001/v1/chunks -H "Content-Type: application/json" \
  -d '{"text":"query","limit":2147483647}'                         # HTTP 200

curl -X POST http://localhost:8001/v1/chunks -H "Content-Type: application/json" \
  -d '{"text":"q","limit":1000,"prev_next_chunks":99999}'          # HTTP 200
```

**Fix:** `limit: int = Field(default=10, ge=1, le=100)` and `prev_next_chunks: int = Field(default=0, ge=0, le=10)`, plus a clamp in the service layer as defense in depth.

## PGPT-003: filenames stored verbatim (low)

The `file_name` from an upload goes straight into document metadata (`ingest_helper.py:76`) and comes back from `GET /v1/ingest/list`. HTML, CRLF sequences, path traversal strings and names longer than 10,000 characters were all accepted and stored unchanged. The bundled UI doesn't render that value unsafely, so I'm treating this as a hardening note rather than a standalone vulnerability: anything built on the API should treat `file_name` as untrusted input.

## Scope

Everything here was tested against PrivateGPT **0.6.2**, using its default configuration, through source review, an automated PoC suite (18 of 18 cases passed) and a live sandbox. Two related issues that were already fixed upstream (null bytes in file content and a local path traversal) are left out. PrivateGPT has since moved to a new 1.x line. If you run it, check your own deployment's auth, bind address and CORS settings rather than relying on the defaults.

## Disclosure timeline

| Date | Event |
|---|---|
| 2026-04-28 | Findings identified and verified against 0.6.2; initial report emailed to the maintainers |
| 2026-07-27 | 90-day disclosure window ends with no response |
| July to September 2026 | Multiple email follow-ups, no response |
| 2026-08-24 | Findings resubmitted as GitHub security advisories through private vulnerability reporting, no response |
| 2026-10-30 | Still no response; details published and CVEs requested through VulDB |
