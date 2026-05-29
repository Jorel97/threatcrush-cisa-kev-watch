# ThreatCrush CISA KEV Watch

Free ThreatCrush module that polls the public CISA Known Exploited Vulnerabilities
catalog and emits one ThreatEvent when a newly added CVE appears in the feed.

The module is intentionally small and production-minded:

- Uses the official CISA KEV JSON feed.
- Requires no private API key.
- Persists `last_seen_date` and `seen_cves` through the ThreatCrush module context.
- Emits structured events with CVE, vendor, product, due date, and mitigation data.
- Ships a `mod.toml` manifest and example daemon config.

## Install

```bash
git clone https://github.com/Jorel97/threatcrush-cisa-kev-watch.git
cd threatcrush-cisa-kev-watch
npm install
npm run build
```

Then copy the example config into your ThreatCrush config directory:

```bash
mkdir -p ~/.threatcrush/threatcrushd.conf.d
cp config/example.conf.toml ~/.threatcrush/threatcrushd.conf.d/cisa-kev-watch.conf.toml
threatcrush stop
threatcrush start
```

## Configuration

Defaults are defined in `mod.toml`.

```toml
[module.config.defaults]
enabled = true
poll_interval_seconds = 3600
feed_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
max_events_per_poll = 25
```

## Event Shape

Each new KEV entry emits a high-severity vulnerability event:

```json
{
  "module": "cisa-kev-watch",
  "category": "vulnerability",
  "severity": "high",
  "message": "CISA KEV: CVE-2026-0001 added for Example Product",
  "details": {
    "cve": "CVE-2026-0001",
    "vendor_project": "Example Vendor",
    "product": "Example Product",
    "date_added": "2026-05-29",
    "due_date": "2026-06-19",
    "known_ransomware_campaign_use": "Unknown"
  }
}
```

## Notes

This module monitors a public government feed and does not claim to exploit,
scan, or validate vulnerabilities on local systems. It is a passive threat
intelligence signal for teams that want newly listed KEV items inside their
ThreatCrush event stream.

