# Self-hosted OpenAI-compatible endpoints

Self-hosted OpenAI-compatible serving is the default enterprise inference
posture: vLLM, llama.cpp server, TGI, NVIDIA NIM, LM Studio, and Ollama all
expose the same `/v1/chat/completions` wire surface. Bernstein can run
coding agents against any of them, and treats "this endpoint is fit for a
role" as a signed, dated claim rather than a folklore note in a wiki.

This page is the operator story for that path: which adapter to point at an
endpoint, which endpoint families the conformance suite has been exercised
against, and the full **certify -> signed record -> verify** loop. The
capability check is the contract, not the engine name -- **anything that
speaks the OpenAI-compatible wire protocol qualifies the same way**, and the
receipt is what proves it.

For the config schema see
[`local_endpoints`](CONFIG.md#local_endpoints-local-model-worker-tier); for
the probe subset, role tiers, and verified single-runtime configurations see
[Local endpoint profiles and certification](../reference/local-endpoints.md).

## Pointing an adapter at an endpoint

The endpoint is a base URL, an optional API key (referenced by the **name**
of an environment variable, never a literal key), and a model id. Any
OpenAI-compatible adapter accepts them per role through a named
`local_endpoints` profile:

```yaml
local_endpoints:
  workhorse:
    base_url: http://127.0.0.1:8000/v1     # any OpenAI-compatible endpoint
    model: Qwen2.5-Coder-7B-Instruct
    engine: vllm                           # free-form label, recorded in the receipt
    timeout: 120                           # request timeout in seconds
    # api_key_env: LOCAL_LLM_API_KEY       # NAME of an env var, never a key

role_model_policy:
  linter:       { endpoint: workhorse }
  test_writer:  { endpoint: workhorse }
```

Adapters that already speak the OpenAI-compatible surface: `ollama`, `qwen`,
`aichat`, and `pydantic_ai` (models given as `<provider>:<model>`). Any CLI
that reads `OPENAI_BASE_URL` / `OPENAI_API_KEY` from the environment can also
be wrapped with the `generic` adapter. `bernstein integrations list` surfaces
the `self-hosted-endpoints` path alongside the adapters.

## Endpoint families

The conformance suite has been exercised against the families below. Each
speaks the OpenAI-compatible wire protocol; the `engine` column is the label
you record in the receipt, not a capability switch.

| Family | Serves | `engine` label |
|---|---|---|
| vLLM | Any HF model, high-throughput serving | `vllm` |
| llama.cpp server | GGUF models on CPU/Metal/CUDA | `llamacpp` |
| Text Generation Inference (TGI) | Hugging Face production serving | `tgi` |
| NVIDIA NIM | Containerized NIM microservices | `nim` |
| LM Studio | Desktop local-model server | `lmstudio` |
| Ollama | Local model runner | `ollama` |

The list is not a closed allowlist. An endpoint from any other stack --
a cloud gateway, an in-house proxy, a runtime not named here -- qualifies by
passing the same probes. Certify it and let the receipt decide; the family
name never enters the verdict.

## Certify -> signed record -> verify

Certification runs a fixed conformance subset (reachability, chat completion,
tool calling, patch-format fidelity, timeout behavior, context floor) with
pinned prompts at `temperature 0`, and seals the transcript plus per-role
verdicts into a signed receipt.

### 1. Certify

```bash
bernstein endpoints certify --base-url http://127.0.0.1:8000/v1 --engine vllm
bernstein endpoints certify --base-url http://127.0.0.1:8000/v1 --role manager
bernstein endpoints certify --base-url http://127.0.0.1:8000/v1 --json
```

- `--model` pins the model id; omit it to take the first entry of the
  endpoint's `/models` listing.
- `--role` (repeatable) evaluates specific roles; the default is the
  low-stakes local tier (`linter`, `test_writer`, `triage`, `doc_sweeper`).
- `--api-key-env` names the environment variable holding the key.
- Exit code: `0` when every evaluated role certified, `1` when at least one
  was rejected (with a machine reason per probe), `2` when no model could be
  resolved.

### 2. The signed record

Each run writes a receipt under
`.sdd/endpoints/certifications/<fingerprint>.json`, where the fingerprint is
the SHA-256 of the normalized `(base_url, model)` pair. The receipt carries:

- the probe transcript and per-role verdicts, bound into canonical JSON;
- an Ed25519 signature by the install's endpoint identity;
- an anchor in the `endpoint-certification` lineage spine run;
- a mirror event (`endpoint.certification`) in the HMAC audit chain.

"Certified" is therefore not a boolean an operator can set: a hand-edited
receipt fails its signature check exactly like a tampered chain entry.

### 3. Verify

Verification is fully offline -- it never contacts the endpoint -- so a
receipt can be re-checked in an air-gapped environment or handed to a
reviewer who was not present at qualification time:

```bash
bernstein endpoints verify --base-url http://127.0.0.1:8000/v1 --model Qwen2.5-Coder-7B-Instruct
bernstein endpoints verify --base-url http://127.0.0.1:8000/v1 --model Qwen2.5-Coder-7B-Instruct --json
```

Verify re-checks, from the stored receipt alone: the endpoint identity, the
Ed25519 signature over the canonical binding, and the certification spine
anchor. Exit code is `0` only when all three hold; an absent, mismatched, or
tampered receipt fails closed.

## Role gating

Low-stakes roles (`linter`, `test_writer`, `triage`, `doc_sweeper`) run on a
certified profile without further ceremony. Every other role is
merge-critical and gated: config validation refuses to assign a gated role
to an endpoint that has no verifying receipt certifying that exact role for
that exact `(base_url, model)` pair, and prints the certify command to run.
The gate fails closed -- a role Bernstein has never seen is gated.

Re-certify after any change that could move a verdict (an engine upgrade,
a model swap, a quantization change): receipts are keyed on `(base_url,
model)`, so switching models re-runs the gate, and re-running certify against
the same pair replaces the receipt in place.
