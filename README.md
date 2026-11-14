# Munimen threat data

Public distribution of signed phishing-host reports for Munimen. This repository contains feed operations tooling and public verification keys. The browser extension and its detection implementation are maintained separately in a private repository.

- [Publication status](https://github.com/poohpak/munimen-threat-data/releases/download/threat-feed/status.json)
- [Signed manifest](https://github.com/poohpak/munimen-threat-data/releases/download/threat-feed/manifest.json)
- [Hourly publication runs](https://github.com/poohpak/munimen-threat-data/actions/workflows/feed.yml)

The manifest URL returns 404 until the first fresh, validated feed can be published. A status-only release is not a functioning phishing list. If the upstream is stale or validation fails, no replacement manifest is published. Existing clients keep their last validated data and treat reports older than 72 hours as advisory.

## Privacy and report meaning

Downloads contain no visitor addresses, search queries, mail content, user identifiers, or browsing history. GitHub receives normal HTTPS connection information. All host checks run on the user's device.

The first source is [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database), which declares the MIT license. When it is unavailable or stale, the reviewed [PhishDestroy primary active domain list](https://github.com/phishdestroy/destroylist) is an MIT-licensed fallback; community aggregated lists are excluded. The manifest identifies the provider actually used. Its `ACTIVE` label is a publisher classification, not independent verification. Exact domain reports and hosts derived from URL reports remain distinct: URL-host reports do not grant permission to block every URL or parent domain.

The upstream license, source revision, file publication times, withdrawals, immutable payload and signed manifest are preserved with each published version. No upstream phishing target is visited by these tools. Source freshness is derived from data-file history, not collection time or an unrelated README commit. All data files of the selected provider must satisfy the 72-hour publication limit. Switching providers does not waive the 25% change guard.

## Reproducing the feed

Node.js 24 and GitHub CLI are used by the publisher:

```sh
npm ci --ignore-scripts
npm test
node scripts/previous-threat-feed.mjs
npm run collect -- --previous=.context/threat-feed/previous.json
npm run sign
npm run publish:feed
```

Signing requires `THREAT_SIGNING_KEY` in the `threat-feed-production` GitHub environment. The private key is never committed or included in artifacts. It is exposed only to the signing step. Only main-branch schedule/manual runs publish data; pull requests do not receive signing credentials. No separate private-repository token is used.

Manifest verification checks the public key, ECDSA P-256/SHA-256 signature, SHA-256 checksums (whole payload and host buckets), monotonically increasing version, schema and timestamps. A host/scope change greater than 25% stops publication. Immutable payloads and audit files are archived in daily `threat-archive-YYYY-MM-DD` releases before the current manifest pointer changes. The stable `threat-feed` release retains only the current and previous payload, keeping hourly updates below per-release asset limits.

An informational status JSON is published even when stale source data blocks publication. It is never an input to the extension's safety decisions. Rollback means re-signing reviewed contents at a higher version while preserving the source timestamp.

## Incorrect reports

Use the upstream [false-positive process](https://github.com/Phishing-Database/Phishing.Database) and retain the host and source evidence for review. Do not submit credentials, mail contents, or URL query strings. Reference-list membership is not a safety guarantee.
