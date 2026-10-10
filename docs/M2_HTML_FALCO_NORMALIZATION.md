# M2 — Versioned HTML and Falco YAML Normalization

**Status:** Implemented against synthetic archives and tested in CI. This is not the original local prototype, and no public CTI source version/case has been approved for the actual research study.

**Tracking:** [Issue #13](https://github.com/FardinSamin/ThreatRAGraph/issues/13)  
**Related:** [M2 exact citation verification](M2_EVIDENCE_ALIGNMENT.md), [M2 graph](M2_EVIDENCE_GRAPH.md), [SRS](SRS.md) FR-02/04/10–12 and [SDD](SDD.md) ``4–7.

## Goal and architecture

A source claim must be traceable to exactly the bytes of an approved archived source version, **even if its evidence is a derived HTML text span or a structured Falco rule field**.

The system never trusts a standalone normalized-text file or a copied YAML field supplied by an extractor. It reads the archived source through its content-addressed SHA-256, rehashes its bytes against the approved manifest, recomputes the normalization/parsing step and evidence excerpt, then compares the evidence SHA-256. Only an exact match can be marked `aligned` in the provenance graph.

~~~mermaid
flowchart TD
    A["Approved source version ID + SHA-256"] --> B["Local immutable source archive"]
    B --> C["Rehash original bytes"]
    C --> D{"Evidence locator kind"}
    D -->|HTML visible text| E["Deterministic html-visible-v1"]
    D -->|Falco field| F["Strict PyYAML 6.0.3"]
    D -->|Plain text / JSON| G["Existing original-byte verifier"]
    E --> H["Resolve cited span"]
    F --> H
    G --> H
    H --> I["Recompute evidence SHA-256"]
    I --> J{"Matches cited digest and permitted historical source?"}
    J -->|Yes| K["Aligned sourced claim, not confirmed truth"]
    J -->|No| L["Reject before graph insertion"]
~~~

The M1 source-approval and M3 B0/G1 cutoff checks still apply. Late held-out reference sources cannot enter the profiler input, regardless of whether an identical-looking citation could be parsed.

## HTML parser contract

**Normalizer identifier:** `html-visible-v1`. **Input:** original UTF-8 HTML archive from an approved `cti_report`, `kubernetes_doc`, `cve_advisory` or `other` source.

The Python standard-library `html.parser.HTMLParser` extracts text nodes, ignores `head`, `script`, `style`, `template`, `noscript`, `iframe`, and `svg` subtrees, converts ordinary HTML character references, and collapses whitespace deterministically. It does **not** execute JavaScript or retrieve remote resources, images or linked CSS.

A derived HTML text locator has *exactly*:

~~~json
{
  "kind": "html_text_span",
  "normalizer_version": "html-visible-v1",
  "segment_id": "seg:SOURCE_VERSION_ID:html-visible-v1",
  "start": 0,
  "end": 12
}
~~~

Offsets are Unicode code-point positions `[start,end)` **inside the entire normalized visible-text string**, **not** raw HTML byte offsets or offsets against an independent unsourced paragraph. The verifier reconstructs this text from original archived bytes each time and hashes the selected substring as UTF-8.

**Fail-closed restrictions:** Invalid UTF-8, missing recognizably HTML structure, unclosed hidden subtree, blank visible content, malformed/wrong normalizer version, source-version-mismatched segment ID, off-end offsets, and forged citation digests are rejected. Bound input and output sizes guard against pathological files.

**Limitations:** HTMLParser is not a fully standards-compliant browser DOM. Dynamic JavaScript content, complex CSS visibility, shadow DOM, CSS pseudoelements, and multimedia are **not extracted**. Source chronology still requires separate proof. The normalized text is useful for human-reviewable CTI quotations, not a semantically authoritative representation of all website content.

## Falco YAML parser contract

**Normalizer identifier:** `falco-safe-yaml-v1-pyyaml-6.0.3`. **Parser:** pinned `PyYAML==6.0.3` from [PyPI](https://pypi.org/project/PyYAML/). CI installs it from [requirements-normalization.txt](../requirements-normalization.txt) before tests.

The parser derives from PyYAML's **SafeLoader**, with additional rejection of:
- YAML aliases and recursive references;
- custom object tags (handled by the underlying safe loader);
- duplicate mapping keys and YAML merge keys;
- invalid UTF-8, oversized files, excessive nesting and malformed rule structures.

It accepts Falco's top-level YAML list of **rules, macros and lists**, preserving strings for rule conditions and field evidence. It does **not** evaluate rule conditions, resolve macros as runtime observations, contact Falco, or assert that an actual container experienced an attack.

A Falco evidence locator has:

~~~json
{
  "kind": "yaml_path",
  "normalizer_version": "falco-safe-yaml-v1-pyyaml-6.0.3",
  "path": "/0/condition"
}
~~~

The path uses JSON Pointer-style indexes/escape rules over the **safely parsed YAML structure**. Falco files usually have a *top-level list*, so `/0/condition` references the first rule's condition. A changed, republished rule is a **different source version** and requires its own approved historical provenance and byte hash.

Only approved source records with `source_kind=falco_rule` may use this locator. **The claim must be `assertion_kind=rule_semantics`**, never an observed incident. A false/missing field, parser-version mismatch or forged evidence hash prevents graph insertion. The quoted condition should be understood as detection logic, not proof a specific syscall was actually observed.

See the Falco [basic rule elements](https://falco.org/docs/concepts/rules/basic-elements/) and [supported fields](https://falco.org/docs/rules/supported-fields/). In particular, `evt.type` is an event field: the graph should not treat every Falco event as an observed syscall occurrence.

## Compatibility and developer setup

Existing plain UTF-8 `text_span` and JSON `json_pointer` references remain supported. A raw-text locator **cannot masquerade as** a whole HTML or PDF document to bypass its normalizer. HTML and YAML locators explicitly pin their own normalization version; older experimental YAML claim fixtures need the new version field before attempting verified insertion. This is a controlled research schema change, not a silently accepted historical rule revision.

~~~powershell
python -m pip install -r requirements-normalization.txt
python -m unittest discover -s tests -v
python -m scripts.project_case_graph --help
~~~

The end-to-end research case CLI automatically uses `EvidenceVerifier`; no extra switch is necessary. Actual runs still require the **approved, rights-reviewed historical sources and cases**, matching local archived bytes, manually reviewed claims and temporal source allowlists. The current project has none of those completed yet.

## Security boundaries and remaining work

- **Byte alignment is not semantic correctness.** The cited words or Falco condition may be interpreted incorrectly. Independent review and extraction quality scoring are still required.
- **The source hash does not prove publication timing.** Historical version/date confirmation remains a separate curator task.
- **No JavaScript, unsafe YAML tags, alias execution, Falco event processing or cloud services** run during normalization.
- PDF page-text extraction is now available with a pinned parser and exact page citation checks (see [PDF provenance](M2_PDF_PAGE_PROVENANCE.md)). **OCR for scanned pages**, dynamic-site browser rendering, visual layout preservation and external normalized segments are **not** implemented. Build a versioned PDF normalizer with deterministic page provenance only after reviewing the original Python prototype and tests.
- Schema evolution, annotation metadata, source licensing, true 25–40-source corpus, 4–6 cases, and full historical GraphRAG evaluation remain open.

**References:** [SRS](SRS.md), [SDD](SDD.md), [Falco rule syntax](https://falco.org/docs/concepts/rules/basic-elements/), [PyYAML 6.0.3](https://pypi.org/project/PyYAML/).
