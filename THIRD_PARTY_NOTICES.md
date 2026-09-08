# Third-party notices

This artifact vendors or derives data from third-party projects. Their names
and attribution identify upstream projects, not the paper authors.

## hackingBuddyGPT

- Upstream: `https://github.com/ipa-lab/hackingBuddyGPT`
- Pinned base commit: `d0ff901fb14ebc67ed91a67232bc0a923957fcd0`
- License: MIT; see `baselines/hackingBuddyGPT/LICENSE`.
- Local changes add the PrivEscAgent bridge plus compatibility updates for
  retries, OpenAI-compatible endpoints, streamed responses, token accounting,
  safe terminal rendering, and Docker root detection.

## HackSynth

- Upstream: `https://github.com/aielte-research/HackSynth`
- Pinned base commit: `48a41f795dda186df66561c4fd2b58ae84e3e4f8`
- License: GNU Affero General Public License v3.0; see
  `baselines/HackSynth/LICENSE.md`.
- Local changes add Anthropic and OpenAI-compatible API support, tolerate
  missing usage fields, and load local-weight dependencies only when needed.

## GTFOBins and Exploit-DB

The artifact includes compact indices and scenario metadata derived from
public GTFOBins and Exploit-DB records. Upstream attribution present in the
records is retained. The source-tree license files captured with the pinned
checkouts are distributed under `dataset/sources/licenses/`: GTFOBins uses
GPL-3.0 and Exploit-DB uses GPL-2.0. Source revisions and acquisition details
are recorded in `docs/DATA_PROVENANCE.md`.
