# Observation pilot v1

Purpose: verify candidate evidence -> fixed sampling -> isolated same-session
URL/DOM/screenshot/browser-network capture -> schema/hash audit -> label review queue.
No model fitting or final benchmark construction. Config and code commit freeze
before network outcomes. One fixed batch: eight curated official controls and eight
seeded phishing-feed candidates, at most one per PSL group. Controls are a census
of the documented engineering control set; only phishing group/URL selection and
execution order are randomized. Record the full feed snapshot/commit before sampling.

Capture uses fresh browser contexts, JavaScript enabled, 1280x720 viewport, en-US,
UTC, a 15-second DOMContentLoaded navigation deadline and fixed 2-second settle.
DOM and viewport screenshot have separate timestamps from the same session;
they are near-synchronous, not an atomic snapshot. Network means browser request,
response/status and failure events, not PCAP, Zeek output or decrypted packet capture.
Record policy-blocked events and missing response sizes rather than inventing values.
Do not equate these observations with unrestricted normal browsing.

The browser runs as a non-root user with Chromium sandbox enabled inside a capped
read-only container on an ephemeral GitHub runner. Its Docker network is internal;
public access goes through a separate proxy that validates every resolved address
and connects to the checked IP. Allow only public TCP 80/443, GET/HEAD/OPTIONS at
browser routing, no WebSockets/service workers/download acceptance/forms. Block
user-info and known token-like query keys before navigation. The proxy has connection,
byte and time caps. Do not disable sandbox, add SYS_ADMIN or relax destination checks
to make a failed pilot pass. Preflight checks proxy denials and browser isolation
before candidates. No GitHub token or personal session enters the capture container.

Fetch robots.txt through the same proxy with bounded size/time and honor disallow.
A 404 permits capture; auth denials, 5xx and unknown fetch failures remain blocked.
Redirected robots responses are treated as unresolved rather than followed off-policy.
The policy limits cross-domain top-level navigation; original redirect evidence is
retained. Third-party subresources may be public and are logged. No source-specific
settings, replacement sampling, early success stopping or model-based selection.

Technical pass requires all 16 planned rows present and schema-valid, all referenced
artifact hashes valid, successful isolation preflight and at least 6 complete captures
in each candidate stratum. A complete capture requires HTTP 2xx HTML with URL, bounded
DOM, screenshot and network log; it does not certify benign/phishing content. CAPTCHA,
parking and soft errors may return 200 and require review. At least 75% completeness
per stratum is a pilot engineering heuristic, not a professor rule or final data gate.

Expansion additionally requires completed label review and two adjudicated classes.
The collector cannot self-certify its source labels. If either gate fails, stop and
report exact counts/reasons. Do not enlarge the sample simply to hide failures.
The next proposed batch is 50 per stratum only after a prospective population/source
frame is frozen; repeatedly taking the same eight official controls would not establish
diverse benign coverage. Existing blocked-environment pilot evidence remains unchanged.

All raw evidence is kept in the private Actions artifact: source snapshot, plan,
attempted/skipped candidates, per-observation assets, network/proxy records, schema,
code/config hashes, versions, failures, review queue and checksum manifest. PR text
contains English aggregate findings only. Captured HTML is untrusted evidence; do
not open it as an active local website. Screenshots are inert review material.

Schema: schemas/observation_v1.schema.json. Implementation: observation.py,
pilot_capture.py, public_proxy.py. Optional browser dependencies are isolated from
the existing URL-only requirements. Existing model/feature/sampling code is retained.

References: https://playwright.dev/python/docs/docker and
https://playwright.dev/python/docs/api/class-browsercontext . Browser image and package
are pinned to 1.63.0. The vendored Playwright seccomp profile is pinned to that tag.
The unmodified profile originates from microsoft/playwright, utils/docker/seccomp_profile.json;
its Apache license is retained at resources/licenses/playwright_APACHE_LICENSE.
