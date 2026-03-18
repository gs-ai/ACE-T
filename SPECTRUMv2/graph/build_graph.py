import json
import hashlib
import math
import os
import sys
import csv
import io
from datetime import datetime, timedelta, timezone
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    pd = None

# Add parent directory to path for imports
sys.path.append('..')

from threat_positioner import ThreatPositioner

BASE_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BASE_DIR.parent

# Local-only: use bundled ingestion in this directory
sys.path.append(str(PROJECT_ROOT))
REALTIME_FEEDS_AVAILABLE = False
fetch_feed = None
THREAT_FEEDS = {}

def _load_threatfox_api_key() -> str:
    key = (os.getenv('THREATFOX_API_KEY') or os.getenv('ABUSECH_AUTH_KEY') or '').strip()
    if key:
        return key
    key_path = PROJECT_ROOT / 'outside_data' / 'threatfox_api_key.txt'
    try:
        if key_path.exists():
            return key_path.read_text().strip()
    except Exception:
        pass
    return ''

def _normalize_threatfox_time(value: str) -> str:
    if not value:
        return ''
    text = str(value).strip()
    if not text:
        return ''
    # ThreatFox often uses "YYYY-MM-DD HH:MM:SS UTC"
    if text.endswith(' UTC'):
        text = text.replace(' UTC', 'Z')
    if ' ' in text and 'T' not in text:
        text = text.replace(' ', 'T')
    return text

# Simple ThreatFox fetcher as fallback
async def simple_fetch_threatfox():
    """Simple ThreatFox fetcher that doesn't depend on the complex realtime module."""
    import aiohttp
    import json
    
    url = "https://threatfox.abuse.ch/export/json/recent/"
    api_url = "https://threatfox-api.abuse.ch/api/v1/"
    api_key = _load_threatfox_api_key()
    records = []
    
    try:
        async with aiohttp.ClientSession() as session:
            feed_data = None
            if api_key:
                try:
                    headers = {"Auth-Key": api_key}
                    payload = {"query": "get_iocs", "days": 7}
                    async with session.post(api_url, json=payload, headers=headers, timeout=30) as response:
                        if response.status != 200:
                            print(f"HTTP {response.status} from ThreatFox API")
                        else:
                            api_json = await response.json()
                            if isinstance(api_json, dict) and api_json.get("query_status") == "ok":
                                feed_data = api_json.get("data", [])
                                print("Loaded ThreatFox via API (Auth-Key).")
                            else:
                                print(f"ThreatFox API returned status: {api_json.get('query_status', 'unknown')}")
                except Exception as e:
                    print(f"ThreatFox API fetch failed, falling back: {e}")

            if feed_data is None:
                async with session.get(url, timeout=30) as response:
                    if response.status != 200:
                        print(f"HTTP {response.status} from ThreatFox")
                        return records
                    data = await response.text()
                    feed_data = json.loads(data)

            ioc_count = 0
            if isinstance(feed_data, dict):
                iterable = []
                # ThreatFox export returns {id: [ioc_objects]}
                for ioc_list in feed_data.values():
                    if isinstance(ioc_list, list):
                        iterable.extend(ioc_list)
            elif isinstance(feed_data, list):
                iterable = feed_data
            else:
                iterable = []

            for entry in iterable:
                if not isinstance(entry, dict):
                    continue

                ioc_type = (entry.get("ioc_type") or "").lower()
                indicator = (entry.get("ioc") or entry.get("ioc_value") or entry.get("indicator") or "").strip()
                if not indicator:
                    continue

                # Map ThreatFox types to ACE-T types
                type_map = {
                    "ip:port": "ip",
                    "domain": "domain",
                    "url": "url",
                    "md5_hash": "hash_md5",
                    "sha256_hash": "hash_sha256",
                    "sha1_hash": "hash_sha1",
                }
                normalized_type = type_map.get(ioc_type, ioc_type.split(":")[0] if ioc_type else "unknown")
                if not normalized_type:
                    normalized_type = "unknown"

                metadata = {
                    "malware": entry.get("malware", "unknown"),
                    "malware_printable": entry.get("malware_printable", ""),
                    "threat_type": entry.get("threat_type", ""),
                    "confidence_level": entry.get("confidence_level", 50),
                    "first_seen": entry.get("first_seen_utc") or entry.get("first_seen") or "",
                    "last_seen": entry.get("last_seen_utc") or entry.get("last_seen") or "",
                    "tags": entry.get("tags", []),
                }

                discovered = _normalize_threatfox_time(metadata.get('first_seen', ''))

                record = {
                    'source': 'Abuse.ch ThreatFox',
                    'category': 'threatfox',
                    'title': indicator,
                    'victim': indicator,
                    'group': metadata.get('malware', 'Unknown'),
                    'sector': 'ThreatFox',
                    'country': '',
                    'subsource': normalized_type,
                    'discovered': discovered or datetime.now().isoformat(),
                    'description': f"ThreatFox {normalized_type}: {indicator} - {metadata.get('malware_printable', metadata.get('malware', 'unknown'))}",
                    'source_url': f"https://threatfox.abuse.ch/browse.php?search=ioc:{indicator}",
                    'url': indicator if normalized_type == 'url' else None,
                    'ioc_type': normalized_type,
                    'ioc_value': indicator,
                    'malware': metadata.get('malware'),
                    'threat_type': metadata.get('threat_type'),
                    'confidence': metadata.get('confidence_level', 50),
                    'tags': metadata.get('tags', []),
                    'first_seen': metadata.get('first_seen'),
                    'last_seen': metadata.get('last_seen')
                }

                if normalized_type == 'ip':
                    record['ip'] = indicator
                elif normalized_type == 'domain':
                    record['domain'] = indicator
                elif normalized_type.startswith('hash_'):
                    record['hash'] = indicator
                    record['hash_type'] = normalized_type

                records.append(record)
                ioc_count += 1

            print(f"Parsed {ioc_count} IOCs from ThreatFox response")
                
    except Exception as e:
        print(f"Error fetching ThreatFox: {e}")
    
    return records

RANSOMWARE_KEYWORDS = (
    'ransomware',
    'locker',
    'leak site',
    'double extortion',
    'lockbit',
    'alphv',
    'blackcat',
    'cl0p',
    'conti',
    'revil',
    'akira',
    'play',
    'rhysida'
)

PRIORITY_LABELS = {
    'SSHv2',
    'DCERPC',
    'EPM',
    'RPC_NETLOGON',
    'HTTP',
    'TLSv1.2',
    'TLSv1.3'
}

VICTIM_CATEGORY_KEYWORDS = {
    'Government': [
        'government', 'ministry', 'agency', 'department', 'federal', 'state', 'county', 'city', 'municipal',
        'public sector', 'township', 'borough'
    ],
    'Education': [
        'school', 'university', 'college', 'academy', 'campus', 'district', '.edu'
    ],
    'Healthcare': [
        'hospital', 'clinic', 'medical', 'healthcare', 'health care', 'pharmacy', 'patient', 'medicine'
    ],
    'Financial Services': [
        'bank', 'credit union', 'financial', 'finance', 'insurance', 'broker', 'investment', 'lending'
    ],
    'Technology': [
        'technology', 'tech', 'software', 'saas', 'it services', 'information technology', 'cloud', 'cyber'
    ],
    'Manufacturing': [
        'manufacturing', 'factory', 'plant', 'industrial', 'production'
    ],
    'Construction': [
        'construction', 'contractor', 'builder', 'engineering', 'civil'
    ],
    'Business Services': [
        'consulting', 'services', 'outsourcing', 'bpo', 'staffing', 'agency'
    ],
    'Transportation': [
        'transport', 'transportation', 'logistics', 'freight', 'shipping', 'airline', 'airport', 'trucking', 'rail', 'port'
    ],
    'Energy': [
        'energy', 'utility', 'power', 'electric', 'oil', 'gas', 'petroleum', 'solar', 'wind'
    ],
    'Law': [
        'law firm', 'law office', 'attorney', 'attorneys', 'lawyers', 'legal', 'llp', 'llc', 'esq', 'counsel'
    ]
}

FEED_TIERS = {
    # Tier 1 — Primary graph drivers
    'ransomware.live': 'tier1',
    'abuse.ch threatfox': 'tier1',
    'abuse.ch urlhaus': 'tier1',
    'abuse.ch feodotracker': 'tier1',
    'abuse.ch ja3': 'tier1',
    'c2intelfeeds': 'tier1',
    'montysecurity c2 tracker': 'tier1',
    'carbon black c2': 'tier1',
    'shadowpad c2': 'tier1',
    # Tier 2 — Infrastructure enrichment only
    'abuse.ch ssl blacklist': 'tier2',
    'abuse.ch ip blacklist': 'tier2',
    'blocklist.de': 'tier2',
    'ipsum': 'tier2',
    'alienvault': 'tier2',
    'binarydefense': 'tier2',
    'proofpoint compromised ips': 'tier2',
    'cinsscore': 'tier2',
    # Tier 3 — Context only
    'cisa kev': 'tier3',
    'nist nvd': 'tier3',
    'cve': 'tier3',
    'ecrimelabs cve': 'tier3',
    'misp cert-fr': 'tier3',
    'apt notes': 'tier3',
    # Tier 4 — Excluded
    'tweetfeed.live': 'tier4',
    'twitter': 'tier4',
    'ace-t intel bundle': 'tier4',
    'live': 'tier4',
}

EXCLUDE_REDDIT = str(os.environ.get('ACE_T_EXCLUDE_REDDIT', '1')).strip().lower() in {'1', 'true', 'yes'}
WRITE_FULL_GRAPH = str(os.environ.get('ACE_T_WRITE_FULL_GRAPH', '0')).strip().lower() in {'1', 'true', 'yes'}

try:
    import yaml  # type: ignore
    YAML_AVAILABLE = True
except Exception:
    YAML_AVAILABLE = False
    yaml = None

CATEGORY_COLORS = {
    'Law': '#ff1a1a',
    'Government': '#5fd1ff',
    'Manufacturing': '#ff7a8a',
    'Technology': '#ff9a3c',
    'Healthcare': '#ffd452',
    'Financial Services': '#43d6c6',
    'Construction': '#7ab6ff',
    'Business Services': '#b27cff',
    'Education': '#c8ced6',
    'Energy': '#5b8cff',
    'Transportation': '#ff8f66',
    'ThreatFox': '#2eda34',
    'URLhaus': '#00c8ff'
}

def _normalize_category_key(value: str) -> str:
    if not value:
        return ''
    return str(value).strip().lower()

def _category_color_for(value: str) -> str | None:
    if not value:
        return None
    key = _normalize_category_key(value)
    for name, color in CATEGORY_COLORS.items():
        if _normalize_category_key(name) == key:
            return color
    # Fuzzy match for composite labels
    for name, color in CATEGORY_COLORS.items():
        needle = _normalize_category_key(name)
        if needle and needle in key:
            return color
    return None

def _stable_rng(seed: str) -> float:
    if seed is None:
        seed = ''
    digest = hashlib.md5(str(seed).encode('utf-8')).hexdigest()
    return int(digest[:8], 16) / 0xFFFFFFFF

def _normalize_source_name(value: str) -> str:
    if value is None:
        return ''
    return str(value).strip().lower()

def _is_threatfox_source(value: str) -> bool:
    key = _normalize_source_name(value)
    return 'threatfox' in key

def _tf_h32(text: str) -> int:
    return int(hashlib.sha1(str(text).encode('utf-8', 'ignore')).hexdigest()[:8], 16)

def _tf_unit(text: str) -> float:
    return (_tf_h32(text) % 10000) / 10000.0

def _tf_norm(value) -> str:
    return str(value or '').strip().lower()

def _tf_parse_ts(value):
    if not value:
        return None
    text = str(value).replace('Z', '+00:00')
    try:
        if text.isdigit():
            return float(text)
        return datetime.fromisoformat(text).timestamp()
    except Exception:
        return None

def _tf_get_node_ts(node: dict):
    for key in ('last_observed', 'first_observed', 'first_seen', 'last_seen', 'timestamp', 'created', 'date', 'posted_at'):
        ts = _tf_parse_ts(node.get(key))
        if ts:
            return ts
    return None

def _tf_looks_like_ip(text: str) -> bool:
    parts = str(text).split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        value = int(part)
        if value < 0 or value > 255:
            return False
    return True

def _tf_ioc_type(node: dict) -> str:
    kind = _tf_norm(node.get('ioc_type') or node.get('subsource') or node.get('kind') or '')
    label = _tf_norm(node.get('label') or node.get('victim_name') or '')
    if 'sha256' in kind or 'md5' in kind or 'sha1' in kind or 'hash' in kind:
        return 'hash'
    if 'domain' in kind:
        return 'domain'
    if 'url' in kind or label.startswith('http'):
        return 'url'
    if 'ip' in kind or _tf_looks_like_ip(label):
        return 'ip'
    if '.' in label and ' ' not in label and '/' not in label and len(label) < 255:
        return 'domain'
    return 'other'

def _tf_family_key(node: dict) -> str:
    fam = _tf_norm(node.get('malware') or node.get('group') or '')
    if fam:
        return fam
    tags = node.get('tags') or []
    if isinstance(tags, list) and tags:
        return _tf_norm(tags[0])
    return 'unknown'

def _tf_time_layer(ts: float, now_ts: float) -> int:
    if not ts:
        return 3
    age_days = (now_ts - ts) / 86400.0
    if age_days <= 1:
        return 0
    if age_days <= 7:
        return 1
    if age_days <= 30:
        return 2
    return 3

def _apply_threatfox_layout(nodes: list) -> dict:
    tf_indices = []
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        if _is_threatfox_source(node.get('source')):
            tf_indices.append(idx)

    if not tf_indices:
        return {}

    # Compute centroid from existing positions
    cx = cy = cz = 0.0
    count = 0
    for idx in tf_indices:
        node = nodes[idx]
        try:
            cx += float(node.get('x') or 0.0)
            cy += float(node.get('y') or 0.0)
            cz += float(node.get('z') or 0.0)
            count += 1
        except Exception:
            continue
    if count > 0:
        cx /= count
        cy /= count
        cz /= count

    # Ensure centroid node exists
    cluster_id = 'tf:cluster'
    centroid = None
    for node in nodes:
        if node.get('id') == cluster_id:
            centroid = node
            break
    if centroid is None:
        centroid = {
            'id': cluster_id,
            'label': 'ThreatFox',
            'kind': 'cluster',
            'victim_name': 'ThreatFox',
            'group': 'ThreatFox',
            'sector': '',
            'country': '',
            'source': _normalize_source_name('abuse.ch threatfox'),
            'source_key': _normalize_source_name('abuse.ch threatfox'),
            'subsource': '',
            'source_url': 'https://threatfox.abuse.ch/',
            'first_observed': datetime.now().isoformat(),
            'last_observed': datetime.now().isoformat(),
            'description': 'ThreatFox cluster centroid',
            'is_cluster': True,
            'collapsed': False,
            'locked': True,
            'x': round(cx, 3),
            'y': round(cy, 3),
            'z': round(cz, 3),
            'source_color': '#39ff14',
            'spectrum_color': '#39ff14',
            'node_color': '#39ff14',
            'glow_color': '#39ff14'
        }
        nodes.append(centroid)

    # Build family sectors
    fams = {}
    for idx in tf_indices:
        fams.setdefault(_tf_family_key(nodes[idx]), 0)
    fam_keys = sorted(fams.keys())
    sector_count = max(8, min(48, len(fam_keys) if fam_keys else 0))
    fam_to_sector = {fam: i for i, fam in enumerate(fam_keys)}

    ring_specs = {
        'hash': {'base_r': 180.0, 'thickness': 70.0, 'z_step': 28.0},
        'domain': {'base_r': 300.0, 'thickness': 90.0, 'z_step': 28.0},
        'url': {'base_r': 440.0, 'thickness': 110.0, 'z_step': 28.0},
        'ip': {'base_r': 600.0, 'thickness': 140.0, 'z_step': 28.0},
        'other': {'base_r': 760.0, 'thickness': 160.0, 'z_step': 28.0}
    }
    now_ts = datetime.now(timezone.utc).timestamp()

    for idx in tf_indices:
        node = nodes[idx]
        nid = str(node.get('id') or '')
        if not nid:
            continue
        ioc = _tf_ioc_type(node)
        spec = ring_specs.get(ioc, ring_specs['other'])
        fam = _tf_family_key(node)
        sec = fam_to_sector.get(fam, 0)
        base_theta = (sec / sector_count) * math.tau if sector_count else 0.0
        jitter = (_tf_unit(f"{nid}|theta") - 0.5) * ((math.tau / max(1, sector_count)) * 0.9)
        theta = base_theta + jitter
        ur = _tf_unit(f"{nid}|r")
        r = spec['base_r'] + (ur - 0.5) * spec['thickness']
        ts = _tf_get_node_ts(node)
        layer = _tf_time_layer(ts, now_ts)
        uz = _tf_unit(f"{nid}|z")
        z = cz + (layer * spec['z_step']) + (uz - 0.5) * 8.0
        if ts:
            age_days = (now_ts - ts) / 86400.0
            theta += (0.10 * math.sin(age_days))
        x = cx + r * math.cos(theta)
        y = cy + r * math.sin(theta)
        node['x'] = round(x, 3)
        node['y'] = round(y, 3)
        node['z'] = round(z, 3)
        node['parent_cluster'] = cluster_id
        node['cluster_source'] = 'THREATFOX'
        node['locked'] = True
        node['node_color'] = '#39ff14'
        node['glow_color'] = '#39ff14'
        node['source_color'] = '#39ff14'
        node['ioc_type'] = ioc
        node['family'] = fam
        node['time_layer'] = layer

    return {'clusters': [{'id': cluster_id, 'source': 'THREATFOX', 'default_collapsed': False}]}

def _apply_urlhaus_layout(nodes: list) -> dict:
    indices = []
    for idx, node in enumerate(nodes):
        if not isinstance(node, dict):
            continue
        if _normalize_source_name(node.get('source')) == 'abuse.ch urlhaus':
            indices.append(idx)

    if not indices:
        return {}

    # Prefer ThreatFox centroid if present to stack the band
    cx = cy = cz = 0.0
    centroid = next((n for n in nodes if n.get('id') == 'tf:cluster'), None)
    if centroid:
        try:
            cx = float(centroid.get('x') or 0.0)
            cy = float(centroid.get('y') or 0.0)
            cz = float(centroid.get('z') or 0.0)
        except Exception:
            cx = cy = cz = 0.0
    else:
        count = 0
        for idx in indices:
            node = nodes[idx]
            try:
                cx += float(node.get('x') or 0.0)
                cy += float(node.get('y') or 0.0)
                cz += float(node.get('z') or 0.0)
                count += 1
            except Exception:
                continue
        if count > 0:
            cx /= count
            cy /= count
            cz /= count

    base_r = 240.0
    thickness = 160.0
    z_spread = 140.0
    z_lift = 220.0
    for idx in indices:
        node = nodes[idx]
        nid = str(node.get('id') or '')
        if not nid:
            continue
        theta = _stable_rng(f"{nid}-theta") * math.tau
        r = base_r + ((_stable_rng(f"{nid}-r") - 0.5) * thickness)
        z = cz + z_lift + ((_stable_rng(f"{nid}-z") - 0.5) * z_spread)
        node['x'] = round(cx + r * math.cos(theta), 3)
        node['y'] = round(cy + r * math.sin(theta), 3)
        node['z'] = round(z, 3)
        node['locked'] = True

    return {}

def _classify_victim_category(*fields: str) -> str:
    text = ' '.join([str(f or '') for f in fields]).lower()
    name_text = str(fields[0] or '').lower() if fields else ''
    if not text:
        return 'Unknown'
    gov_strong = [
        'sheriff', 'police', 'law enforcement', 'department', 'bureau',
        'county', 'city', 'municipal', 'public sector', 'ministry', 'agency',
        'township', 'borough'
    ]
    gov_lock = ['sheriff', 'police', 'law enforcement']
    education_hit = any(kw in text for kw in VICTIM_CATEGORY_KEYWORDS.get('Education', []))
    law_hit = any(kw in name_text for kw in VICTIM_CATEGORY_KEYWORDS.get('Law', []))
    if not law_hit:
        law_hit = any(kw in text for kw in VICTIM_CATEGORY_KEYWORDS.get('Law', []))
    if not law_hit:
        if ' law ' in f" {text} " or text.endswith(' law') or text.startswith('law '):
            law_hit = True
    if law_hit and not education_hit and not any(kw in name_text for kw in gov_lock):
        return 'Law'
    if any(kw in name_text for kw in gov_strong):
        return 'Government'
    if 'government' in text:
        return 'Government'
    priority = [
        'Education', 'Healthcare', 'Financial Services', 'Technology',
        'Manufacturing', 'Construction', 'Business Services', 'Transportation', 'Energy', 'Government'
    ]
    for category in priority:
        for kw in VICTIM_CATEGORY_KEYWORDS.get(category, []):
            if kw in text:
                return category
    return 'Unknown'

def get_feed_tier(source: str) -> str:
    normalized = _normalize_source_name(source)
    if not normalized:
        return 'tier4'
    return FEED_TIERS.get(normalized, 'tier4')

def is_tier1_source(source: str) -> bool:
    return get_feed_tier(source) == 'tier1'

def _load_ingest_sources_config() -> dict:
    config_path = PROJECT_ROOT / 'config' / 'ingest_sources.yaml'
    if not YAML_AVAILABLE or not config_path.exists():
        return {}
    try:
        payload = yaml.safe_load(config_path.read_text(encoding='utf-8')) or {}
        return payload if isinstance(payload, dict) else {}
    except Exception:
        return {}

def _build_allowed_sources() -> set:
    cfg = _load_ingest_sources_config()
    allowed = set()
    # primary incidents
    ransomware_cfg = cfg.get('ransomware_live', {}) if isinstance(cfg, dict) else {}
    if isinstance(ransomware_cfg, dict) and ransomware_cfg.get('enabled'):
        allowed.add('ransomware.live')
        allowed.add('ransomware_live')

    # infrastructure feeds
    abuse_cfg = cfg.get('abuse_ch', {}) if isinstance(cfg, dict) else {}
    if isinstance(abuse_cfg, dict):
        for name, entry in abuse_cfg.items():
            if isinstance(entry, dict) and entry.get('enabled'):
                allowed.add(str(name))
                allowed.add(f"abuse.ch {name}")
    c2_cfg = cfg.get('c2_intel', {}) if isinstance(cfg, dict) else {}
    if isinstance(c2_cfg, dict):
        for name, entry in c2_cfg.items():
            if isinstance(entry, dict) and entry.get('enabled'):
                allowed.add(str(name))

    # reputation feeds
    rep_cfg = cfg.get('reputation', {}) if isinstance(cfg, dict) else {}
    if isinstance(rep_cfg, dict):
        for name, entry in rep_cfg.items():
            if isinstance(entry, dict) and entry.get('enabled'):
                allowed.add(str(name))

    # background feeds
    bg_cfg = cfg.get('background', {}) if isinstance(cfg, dict) else {}
    if isinstance(bg_cfg, dict):
        for name, entry in bg_cfg.items():
            if isinstance(entry, dict) and entry.get('enabled'):
                allowed.add(str(name))

    if not allowed:
        allowed.add('ransomware.live')
    return { _normalize_source_name(s) for s in allowed if s }

ALLOWED_SOURCES = _build_allowed_sources()

def _is_allowed_source(source: str) -> bool:
    if not source:
        return False
    return _normalize_source_name(source) in ALLOWED_SOURCES

def _contains_ransomware(text: str) -> bool:
    if not text:
        return False
    lowered = str(text).lower()
    return any(keyword in lowered for keyword in RANSOMWARE_KEYWORDS)

def _parse_datetime(value):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        numeric = float(value)
        if numeric > 1_000_000_000_000:
            return datetime.fromtimestamp(numeric / 1000.0, tz=timezone.utc)
        if numeric > 1_000_000_000:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
        return None
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return None
        try:
            return datetime.fromisoformat(raw.replace('Z', '+00:00')).astimezone(timezone.utc)
        except Exception:
            pass
        try:
            numeric = float(raw)
        except ValueError:
            return None
        if numeric > 1_000_000_000_000:
            return datetime.fromtimestamp(numeric / 1000.0, tz=timezone.utc)
        if numeric > 1_000_000_000:
            return datetime.fromtimestamp(numeric, tz=timezone.utc)
    return None

def is_older_than_days(record: dict, days: int, now=None) -> bool:
    if not record:
        return False
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=days)
    timestamp_fields = (
        'timestamp', 'time', 'Time', 'received_at',
        'discovered', 'date', 'discovered_at',
        'first_seen', 'last_seen', 'first_observed', 'last_observed'
    )
    for field in timestamp_fields:
        if field in record:
            parsed = _parse_datetime(record.get(field))
            if parsed:
                return parsed < cutoff
    return False

def is_ransomware_threat(threat: dict) -> bool:
    category = threat.get('category', '')
    if _contains_ransomware(category):
        return True

    indicators = threat.get('indicators', {})
    for key in ('malware', 'group', 'actor'):
        if _contains_ransomware(indicators.get(key, '')):
            return True

    metadata = threat.get('metadata', {})
    for key in ('reporting_source', 'description', 'notes', 'predicted_label', 'attack_type'):
        if _contains_ransomware(metadata.get(key, '')):
            return True

    return False

def sanitize_prior_state(prior_state: dict) -> dict:
    threats = prior_state.get('threats', [])
    filtered_threats = [
        threat for threat in threats
        if threat.get('category') != 'OSINT_Resource' and threat.get('source') != 'OSINT_Dataset'
    ]
    valid_ids = {threat.get('id') for threat in filtered_threats}
    fingerprint_index = prior_state.get('index', {}).get('fingerprint_to_threat_id', {})
    filtered_index = {
        fingerprint: threat_id
        for fingerprint, threat_id in fingerprint_index.items()
        if threat_id in valid_ids
    }
    return {'threats': filtered_threats, 'index': {'fingerprint_to_threat_id': filtered_index}}

def _load_ransomware_live_cache(cache_path: Path) -> dict:
    if cache_path.exists():
        try:
            with open(cache_path, 'r') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_ransomware_live_cache(cache_path: Path, payload: dict) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, 'w') as f:
            json.dump(payload, f, indent=2)
    except Exception:
        pass

def _extract_ransomware_live_victims(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for key in ('victims', 'data', 'items', 'results'):
            value = payload.get(key)
            if isinstance(value, list):
                return value
    return []

def _apply_victim_category(victims: list, category: str | None) -> list:
    if not category:
        return victims
    for victim in victims:
        if not isinstance(victim, dict):
            continue
        existing = victim.get('victim_category') or victim.get('ace_category')
        if category == 'Government':
            if existing != 'Government':
                victim['victim_category'] = category
            continue
        existing_norm = str(existing or '').strip().lower()
        category_norm = str(category or '').strip().lower()
        if existing_norm == 'law' and category_norm and category_norm != 'law':
            victim['victim_category'] = category
            continue
        if not existing or existing_norm in {'unknown', 'n/a', 'na'}:
            victim['victim_category'] = category
    return victims

def _build_ransomware_live_query_plan(cfg: dict) -> list[tuple[str, str | None]]:
    query_terms = []
    if isinstance(cfg, dict):
        raw_terms = cfg.get('query_terms')
        if isinstance(raw_terms, list):
            query_terms = [str(t).strip() for t in raw_terms if str(t).strip()]
    if not query_terms:
        query_terms = [os.environ.get('RANSOMWARE_LIVE_QUERY', cfg.get('query', 'law'))]

    category_queries = []
    if isinstance(cfg, dict):
        raw_categories = cfg.get('category_queries')
        if isinstance(raw_categories, dict):
            for category, terms in raw_categories.items():
                if not terms:
                    continue
                if isinstance(terms, (list, tuple)):
                    cat_terms = [str(t).strip() for t in terms if str(t).strip()]
                else:
                    cat_terms = [str(terms).strip()] if str(terms).strip() else []
                for term in cat_terms:
                    category_queries.append((term, str(category).strip()))

    if not category_queries:
        defaults = {
            'Government': ['government', 'sheriff', 'police', 'county'],
            'Education': ['school', 'university', 'college'],
            'Healthcare': ['hospital', 'clinic', 'medical'],
            'Financial Services': ['bank', 'credit union', 'insurance'],
            'Technology': ['technology', 'software', 'it services'],
            'Manufacturing': ['manufacturing', 'factory', 'plant'],
            'Construction': ['construction', 'engineering', 'contractor'],
            'Business Services': ['consulting', 'services', 'agency'],
            'Transportation': ['transport', 'logistics', 'shipping'],
            'Energy': ['energy', 'utility', 'oil']
        }
        for category, terms in defaults.items():
            for term in terms:
                category_queries.append((term, category))

    plan = []
    for term in query_terms:
        plan.append((term, 'Law'))
    plan.extend(category_queries)

    priority_order = ['Government', 'Law'] + [k for k in VICTIM_CATEGORY_KEYWORDS.keys() if k not in {'Law', 'Government'}]
    priority = {name: idx for idx, name in enumerate(priority_order)}
    term_to_category: dict[str, str | None] = {}
    for term, category in plan:
        key = str(term).strip().lower()
        if not key:
            continue
        existing = term_to_category.get(key)
        if existing is None:
            term_to_category[key] = category
            continue
        if existing == 'Law':
            continue
        if category == 'Law':
            term_to_category[key] = category
            continue
        if priority.get(category, 999) < priority.get(existing, 999):
            term_to_category[key] = category

    return [(term, term_to_category.get(term.lower())) for term in term_to_category.keys()]

def load_ransomware_live_victims():
    """Load ransomware.live victims with strict call limits and local caching."""
    api_key = os.environ.get('RANSOMWARE_LIVE_API_KEY')
    if not api_key:
        key_file = PROJECT_ROOT / 'outside_data' / 'ransomware_live_api_key.txt'
        if key_file.exists():
            try:
                api_key = key_file.read_text().strip()
            except Exception:
                api_key = None

    if not api_key:
        return []

    cfg = _load_ingest_sources_config()
    ransomware_cfg = cfg.get('ransomware_live', {}) if isinstance(cfg, dict) else {}
    query_plan = _build_ransomware_live_query_plan(ransomware_cfg)
    if not query_plan:
        fallback = os.environ.get('RANSOMWARE_LIVE_QUERY', 'law')
        query_plan = [(str(fallback).strip(), 'Law')]

    order = os.environ.get('RANSOMWARE_LIVE_ORDER', ransomware_cfg.get('order', 'discovered'))
    is_live_mode = os.environ.get('ACE_T_LIVE_MODE', '').lower() in ('1', 'true', 'yes')
    min_interval_minutes = int(os.environ.get('RANSOMWARE_LIVE_MIN_INTERVAL_MINUTES', '5' if is_live_mode else '60'))
    max_daily_calls = int(os.environ.get('RANSOMWARE_LIVE_DAILY_LIMIT', '200'))

    cache_path = PROJECT_ROOT / 'outside_data' / 'ransomware_live_cache.json'
    cache = _load_ransomware_live_cache(cache_path)

    today = datetime.now(timezone.utc).date().isoformat()
    daily_count = int(cache.get('daily_count', 0))
    cache_date = cache.get('daily_date')
    if cache_date != today:
        daily_count = 0
        cache['query_cache'] = {}

    query_cache = cache.get('query_cache', {}) if isinstance(cache.get('query_cache', {}), dict) else {}
    all_victims = []

    for term, category in query_plan:
        if daily_count >= max_daily_calls:
            break
        term_key = str(term).strip().lower()
        term_cache = query_cache.get(term_key, {})

        last_fetch_raw = term_cache.get('last_fetch_utc')
        last_fetch = None
        if last_fetch_raw:
            try:
                last_fetch = datetime.fromisoformat(last_fetch_raw.replace('Z', '+00:00'))
            except Exception:
                last_fetch = None

        if last_fetch:
            elapsed = datetime.now(timezone.utc) - last_fetch.replace(tzinfo=timezone.utc)
            if elapsed < timedelta(minutes=min_interval_minutes):
                cached = _extract_ransomware_live_victims(term_cache.get('data', {}))
                all_victims.extend(_apply_victim_category(cached, category))
                continue

        params = urllib.parse.urlencode({'q': term, 'order': order})
        url = f"https://api-pro.ransomware.live/victims/search?{params}"
        req = urllib.request.Request(url, headers={
            'accept': 'application/json',
            'X-API-KEY': api_key
        })

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = resp.read().decode('utf-8')
                payload = json.loads(body)
        except Exception:
            cached = _extract_ransomware_live_victims(term_cache.get('data', {}))
            all_victims.extend(_apply_victim_category(cached, category))
            continue

        term_cache = {
            'last_fetch_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'data': payload
        }
        query_cache[term_key] = term_cache
        daily_count += 1
        fresh = _extract_ransomware_live_victims(payload)
        all_victims.extend(_apply_victim_category(fresh, category))

    if daily_count >= max_daily_calls and not all_victims:
        for term, category in query_plan:
            term_key = str(term).strip().lower()
            term_cache = query_cache.get(term_key, {})
            cached = _extract_ransomware_live_victims(term_cache.get('data', {}))
            all_victims.extend(_apply_victim_category(cached, category))

    cache_payload = {
        'daily_date': today,
        'daily_count': daily_count,
        'query_cache': query_cache,
        'queries': [term for term, _ in query_plan]
    }
    _save_ransomware_live_cache(cache_path, cache_payload)

    # de-dupe victims by id/permalink/title
    deduped_map = {}
    for victim in all_victims:
        if not isinstance(victim, dict):
            continue
        key = victim.get('id') or victim.get('permalink') or victim.get('post_url') or victim.get('post_title')
        key = str(key or '').strip()
        if not key:
            continue
        existing = deduped_map.get(key)
        if not existing:
            deduped_map[key] = victim
            continue
        existing_cat = existing.get('victim_category') or existing.get('ace_category')
        new_cat = victim.get('victim_category') or victim.get('ace_category')
        existing_norm = str(existing_cat or '').strip().lower()
        new_norm = str(new_cat or '').strip().lower()
        if existing_norm == 'government' and new_norm and new_norm != 'government':
            continue
        if new_cat == 'Government' and existing_norm != 'government':
            existing['victim_category'] = new_cat
        elif existing_norm == 'law' and new_norm and new_norm != 'law':
            existing['victim_category'] = new_cat
        elif new_norm and (not existing_cat or existing_norm in {'unknown', 'n/a', 'na'}):
            existing['victim_category'] = new_cat

    return list(deduped_map.values())

def load_twitter_threats():
    """Load threat intelligence from TweetFeed.live API."""
    import time
    import urllib.request
    import urllib.error

    if not is_tier1_source('TweetFeed.live'):
        print("TweetFeed.live excluded by ingestion governance")
        return []

    if str(os.environ.get('TWEETFEED_DISABLED', '')).lower() in {'1', 'true', 'yes'}:
        print("TweetFeed.live disabled via TWEETFEED_DISABLED")
        return []

    records = []
    max_records = int(os.environ.get('TWEETFEED_MAX_RECORDS', '120'))
    timeout = int(os.environ.get('TWEETFEED_TIMEOUT', '10'))
    max_retries = int(os.environ.get('TWEETFEED_MAX_RETRIES', '2'))

    api_key = os.environ.get('TWEETFEED_API_KEY')
    user_agent = os.environ.get(
        'TWEETFEED_USER_AGENT',
        'ACE-T-SPECTRUM/1.0 (+https://example.local)'
    )

    headers = {
        'accept': 'application/json',
        'user-agent': user_agent,
        'cache-control': 'no-cache'
    }
    if api_key:
        headers['X-API-Key'] = api_key

    # Define API endpoints to try (prioritize ransomware-related)
    endpoints = [
        'https://api.tweetfeed.live/v1/week/ransomware',
        'https://api.tweetfeed.live/v1/week/phishing',
        'https://api.tweetfeed.live/v1/week/cobaltstrike',
        'https://api.tweetfeed.live/v1/month/ransomware',
    ]
    fallback_endpoints = [
        'https://api.tweetfeed.live/v1/today',
        'https://api.tweetfeed.live/v1/week',
    ]
    focus_tags = {'ransomware', 'phishing', 'cobaltstrike'}
    seen = set()
    saw_forbidden = False

    def _item_key(item):
        return (item.get('value'), item.get('type'), item.get('tweet'), item.get('date'))

    def _append_item(item):
        if not isinstance(item, dict):
            return
        key = _item_key(item)
        if key in seen:
            return
        seen.add(key)
        records.append({
            'source': 'TweetFeed.live',
            'category': 'twitter_threat',
            'title': f"Twitter IOC: {item.get('value', 'Unknown')}",
            'group': 'Unknown',
            'sector': 'Unknown',
            'country': 'Unknown',
            'discovered': item.get('date', datetime.now().isoformat()),
            'description': f"Twitter threat: {item.get('type', 'unknown')} - {item.get('value', '')}",
            'url': item.get('tweet'),
            'ioc_type': item.get('type'),
            'ioc_value': item.get('value'),
            'tags': item.get('tags', []),
            'user': item.get('user')
        })

    def _fetch_endpoint(endpoint):
        nonlocal saw_forbidden
        for attempt in range(max_retries + 1):
            try:
                print(f"Fetching Twitter threats from: {endpoint}")
                req = urllib.request.Request(endpoint, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    data = json.loads(response.read().decode('utf-8'))
                if isinstance(data, list):
                    for item in data:
                        _append_item(item)
                return True
            except urllib.error.HTTPError as e:
                if e.code == 403:
                    saw_forbidden = True
                print(f"HTTP error fetching {endpoint}: {e.code}")
                if e.code in (403, 429, 500, 502, 503, 504) and attempt < max_retries:
                    time.sleep(1.5 * (attempt + 1))
                    continue
                return False
            except urllib.error.URLError as e:
                print(f"URL error fetching {endpoint}: {e.reason}")
                if attempt < max_retries:
                    time.sleep(1.2 * (attempt + 1))
                    continue
                return False
            except Exception as e:
                print(f"Error fetching {endpoint}: {e}")
                return False

    for endpoint in endpoints:
        _fetch_endpoint(endpoint)
        if len(records) >= max_records:
            break

    if len(records) < max_records:
        for endpoint in fallback_endpoints:
            ok = _fetch_endpoint(endpoint)
            if not ok:
                continue
            if not records:
                continue
            # Filter fallback payload to focus tags if tags present
            filtered = []
            for item in records:
                tags = item.get('tags') or []
                tags_lower = {str(t).lower().lstrip('#') for t in tags}
                ioc_type = str(item.get('ioc_type', '')).lower()
                if tags_lower & focus_tags or ioc_type in focus_tags:
                    filtered.append(item)
            if filtered:
                records = filtered
            if len(records) >= max_records:
                break

    if saw_forbidden and not records:
        print("TweetFeed.live returned 403; skipping Twitter feed until access is restored.")

    if len(records) > max_records:
        records = records[:max_records]

    return records

def load_threatfox():
    """Load threat intelligence from Abuse.ch ThreatFox."""
    import asyncio
    import aiohttp

    if not is_tier1_source('abuse.ch threatfox'):
        print("Abuse.ch ThreatFox excluded by ingestion governance")
        return []

    records = []

    async def _fetch_threatfox():
        nonlocal records
        if REALTIME_FEEDS_AVAILABLE and THREAT_FEEDS:
            # Use the full module if available
            print("Using full realtime feeds module for ThreatFox")
            feed_config = THREAT_FEEDS.get('threatfox')
            if not feed_config:
                print("ThreatFox config not found")
                return

            print(f"Fetching ThreatFox from: {feed_config.get('url')}")
            async with aiohttp.ClientSession() as session:
                url = feed_config["url"]
                async with session.get(url, timeout=30) as response:
                    if response.status != 200:
                        print(f"HTTP {response.status} from ThreatFox")
                        return
                    
                    data = await response.text()
                    feed_data = json.loads(data)
                    
                    # ThreatFox returns {id: [ioc_objects]}
                    ioc_count = 0
                    for ioc_list in feed_data.values():
                        if not isinstance(ioc_list, list):
                            continue
                        for entry in ioc_list:
                            if not isinstance(entry, dict):
                                continue
                            
                            ioc_type = entry.get("ioc_type", "").lower()
                            indicator = entry.get("ioc_value", "").strip()
                            if not indicator:
                                continue

                            # Map ThreatFox types to ACE-T types
                            type_map = {
                                "ip:port": "ip",
                                "domain": "domain",
                                "url": "url",
                                "md5_hash": "hash_md5",
                                "sha256_hash": "hash_sha256",
                            }
                            normalized_type = type_map.get(ioc_type, ioc_type.split(":")[0] if ioc_type else "unknown")
                            if not normalized_type:
                                normalized_type = "unknown"

                            metadata = {
                                "malware": entry.get("malware", "unknown"),
                                "malware_printable": entry.get("malware_printable", ""),
                                "threat_type": entry.get("threat_type", ""),
                                "confidence_level": entry.get("confidence_level", 50),
                                "first_seen": entry.get("first_seen_utc", ""),
                                "last_seen": entry.get("last_seen_utc", ""),
                                "tags": entry.get("tags", []),
                            }

                            # Convert ThreatFox date format to ISO
                            discovered = metadata.get('first_seen', '')
                            if discovered and ' ' in discovered and 'T' not in discovered:
                                # Convert "2026-01-30 15:19:28" to "2026-01-30T15:19:28Z"
                                discovered = discovered.replace(' ', 'T') + 'Z'

                            # Create record for the IOC
                            record = {
                                'source': 'Abuse.ch ThreatFox',
                                'category': 'threatfox',
                                'title': indicator,
                                'victim': indicator,
                                'group': metadata.get('malware', 'Unknown'),
                                'sector': 'ThreatFox',
                                'country': '',
                                'subsource': normalized_type,
                                'discovered': discovered or datetime.now().isoformat(),
                                'description': f"ThreatFox {normalized_type}: {indicator} - {metadata.get('malware_printable', metadata.get('malware', 'unknown'))}",
                                'source_url': f"https://threatfox.abuse.ch/browse.php?search={indicator}",
                                'url': indicator if normalized_type == 'url' else None,
                                'ioc_type': normalized_type,
                                'ioc_value': indicator,
                                'malware': metadata.get('malware'),
                                'threat_type': metadata.get('threat_type'),
                                'confidence': metadata.get('confidence_level', 50),
                                'tags': metadata.get('tags', []),
                                'first_seen': metadata.get('first_seen'),
                                'last_seen': metadata.get('last_seen')
                            }
                            
                            # Add additional fields based on IOC type
                            if normalized_type == 'ip':
                                record['ip'] = indicator
                            elif normalized_type == 'domain':
                                record['domain'] = indicator
                            elif normalized_type.startswith('hash_'):
                                record['hash'] = indicator
                                record['hash_type'] = normalized_type
                            
                            records.append(record)
                            ioc_count += 1
                    
                    print(f"Parsed {ioc_count} IOCs from ThreatFox response")
        else:
            # Use simple fetcher
            print("Using simple ThreatFox fetcher")
            records.extend(await simple_fetch_threatfox())

    # Run the async fetch
    asyncio.run(_fetch_threatfox())
    
    print(f"Loaded {len(records)} ThreatFox IOCs")
    return records

def load_urlhaus():
    """Load URLhaus malicious URL feed (recent)."""
    if not is_tier1_source('abuse.ch urlhaus'):
        print("Abuse.ch URLhaus excluded by ingestion governance")
        return []

    cfg = _load_ingest_sources_config()
    abuse_cfg = cfg.get('abuse_ch', {}) if isinstance(cfg, dict) else {}
    urlhaus_cfg = abuse_cfg.get('urlhaus', {}) if isinstance(abuse_cfg, dict) else {}
    url = (urlhaus_cfg.get('url') if isinstance(urlhaus_cfg, dict) else None) or "https://urlhaus.abuse.ch/downloads/csv_recent/"
    timeout = int(os.environ.get('URLHAUS_TIMEOUT', '12'))
    max_records = int(os.environ.get('URLHAUS_MAX_RECORDS', '2000'))

    records = []
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'ACE-T-SPECTRUM/1.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode('utf-8', errors='replace')
    except Exception as e:
        print(f"Error fetching URLhaus: {e}")
        return records

    header_line = None
    data_lines = []
    for line in payload.splitlines():
        if not line or not line.strip():
            continue
        stripped = line.lstrip()
        if stripped.startswith('#'):
            header_candidate = stripped.lstrip('#').strip()
            if header_candidate.lower().startswith('id,'):
                header_line = header_candidate
            continue
        data_lines.append(line)

    if not data_lines:
        return records

    if header_line:
        lines = [header_line] + data_lines
    else:
        lines = data_lines

    reader = csv.reader(lines)
    rows = list(reader)
    if not rows:
        return records

    header = [h.strip().lower() for h in rows[0]]
    idx = {name: i for i, name in enumerate(header)}

    def _get(row, key):
        i = idx.get(key)
        if i is None or i >= len(row):
            return ''
        return str(row[i]).strip()

    for row in rows[1:]:
        if not row:
            continue
        url_value = _get(row, 'url')
        if not url_value:
            continue
        threat = _get(row, 'threat')
        tags_raw = _get(row, 'tags')
        tags = [t.strip() for t in tags_raw.split(',') if t.strip()] if tags_raw else []
        url_status = _get(row, 'url_status')
        last_online = _get(row, 'last_online')
        date_added = _get(row, 'dateadded') or _get(row, 'date_added')
        urlhaus_link = _get(row, 'urlhaus_link')

        description_parts = [f"URLhaus {threat or 'malicious'}: {url_value}"]
        if url_status:
            description_parts.append(f"Status: {url_status}")
        if last_online:
            description_parts.append(f"Last online: {last_online}")
        if tags:
            description_parts.append(f"Tags: {', '.join(tags)}")

        record = {
            'source': 'Abuse.ch URLhaus',
            'category': 'urlhaus',
            'title': url_value,
            'victim': url_value,
            'group': threat or 'Unknown',
            'sector': 'URLhaus',
            'country': '',
            'subsource': 'url',
            'discovered': date_added or datetime.now().isoformat(),
            'description': ' | '.join(description_parts),
            'source_url': urlhaus_link or url_value,
            'url': url_value,
            'ioc_type': 'url',
            'ioc_value': url_value,
            'tags': tags,
            'threat': threat,
            'last_seen': last_online,
            'victim_domain': _extract_domain(url_value)
        }
        records.append(record)
        if len(records) >= max_records:
            break

    print(f"Loaded {len(records)} URLhaus records")
    return records

def _log_source_summary(records: list, label: str) -> None:
    if not records:
        print(f"{label}: 0 records")
        return
    counts = {}
    for r in records:
        source = r.get('source', 'Unknown')
        counts[source] = counts.get(source, 0) + 1
    summary = ', '.join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"{label}: {len(records)} records ({summary})")

def _normalize_records(records: list) -> None:
    fixes = {'title': 0, 'discovered': 0}
    for record in records:
        if not isinstance(record, dict):
            continue
        if record.get('source') == 'Original SPECTRUM Graph':
            continue
        if not record.get('title'):
            candidate = record.get('victim') or record.get('name') or record.get('value')
            if candidate:
                record['title'] = candidate
                fixes['title'] += 1
        discovered = record.get('discovered') or record.get('date') or record.get('timestamp')
        parsed = _parse_datetime(discovered)
        if parsed:
            record['discovered'] = parsed.isoformat()
            fixes['discovered'] += 1
    if fixes['title'] or fixes['discovered']:
        print(f"Normalized records: titles={fixes['title']} timestamps={fixes['discovered']}")

def _extract_domain(value: str) -> str:
    if not value:
        return ''
    text = str(value).strip()
    if not text:
        return ''
    try:
        from urllib.parse import urlparse
        parsed = urlparse(text if '://' in text else f'//{text}', scheme='https')
        host = parsed.netloc or parsed.path
    except Exception:
        host = text
    if '@' in host:
        host = host.rsplit('@', 1)[-1]
    if ':' in host:
        host = host.split(':', 1)[0]
    host = host.lower()
    host = host.strip().strip('.')
    if '/' in host:
        host = host.split('/', 1)[0]
    return host

def _is_same_or_subdomain(host: str, base_domain: str) -> bool:
    host_text = str(host or '').strip().lower().strip('.')
    base_text = str(base_domain or '').strip().lower().strip('.')
    if not host_text or not base_text:
        return False
    return host_text == base_text or host_text.endswith(f".{base_text}")

def _is_domain_reference(value: str, base_domain: str) -> bool:
    return _is_same_or_subdomain(_extract_domain(value), base_domain)

def _derive_source_from_url(url: str, fallback: str) -> str:
    domain = _extract_domain(url)
    if domain:
        if _is_same_or_subdomain(domain, 'reddit.com'):
            return 'reddit.com'
        if _is_same_or_subdomain(domain, 'ransomware.live'):
            return 'ransomware.live'
        return domain
    return fallback or 'unknown'

def _is_reddit_reference(value: str) -> bool:
    if not value:
        return False
    return _is_domain_reference(value, 'reddit.com')

def _is_law_match(*values: str) -> bool:
    for value in values:
        if value and 'law' in str(value).lower():
            return True
    return False

def _source_color_for(source: str) -> str:
    key = (source or '').lower()
    if not key:
        return '#00E5FF'
    h = 0
    for ch in key:
        h = ((h << 5) - h) + ord(ch)
        h &= 0xFFFFFFFF
    hue = abs(h) % 360
    sat = 70
    light = 52
    h_norm = hue / 360.0
    s = sat / 100.0
    l = light / 100.0
    if s == 0:
        r = g = b = l
    else:
        def hue2rgb(p, q, t):
            if t < 0:
                t += 1
            if t > 1:
                t -= 1
            if t < 1/6:
                return p + (q - p) * 6 * t
            if t < 1/2:
                return q
            if t < 2/3:
                return p + (q - p) * (2/3 - t) * 6
            return p
        q = l * (1 + s) if l < 0.5 else l + s - l * s
        p = 2 * l - q
        r = hue2rgb(p, q, h_norm + 1/3)
        g = hue2rgb(p, q, h_norm)
        b = hue2rgb(p, q, h_norm - 1/3)
    return f"#{int(r*255):02x}{int(g*255):02x}{int(b*255):02x}"

def _write_sources_json(nodes: list) -> None:
    sources = {}
    for node in nodes:
        if not isinstance(node, dict):
            continue
        raw_source = node.get('source_key') or node.get('source') or node.get('subsource')
        if not raw_source:
            continue
        source = str(raw_source).strip().lower()
        if not source:
            continue
        if source in sources:
            continue
        color = node.get('source_color') or node.get('spectrum_color') or node.get('color')
        sources[source] = color or _source_color_for(source)
    if not sources:
        return
    payload = {
        'sources': [{'name': name, 'color': color} for name, color in sorted(sources.items())]
    }
    out_dir = BASE_DIR / 'data'
    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / 'sources.json'
    _atomic_write_json(out_path, payload)

def _atomic_write_json(path: Path, payload: dict) -> None:
    tmp_path = path.with_suffix(path.suffix + '.tmp')
    with open(tmp_path, 'w') as f:
        json.dump(payload, f, indent=2)
    tmp_path.replace(path)

def _build_render_edges(edges: list, max_edges_per_node: int = 6, allowed_types=None) -> list:
    priority = {
        'SAME_GROUP': 1,
        'TIME_CLUSTER': 2,
        'DOMAIN_PATTERN_MATCH': 3,
        'GROUP_SECTOR_OVERLAP': 4,
        'GROUP_COUNTRY_OVERLAP': 5,
        'CROSS_GROUP_SECTOR': 6
    }
    allowed = set(allowed_types) if allowed_types else None
    counts = {}
    selected = []
    def _edge_key(e):
        return (priority.get(e.get('type'), 99), str(e.get('source')), str(e.get('target')), str(e.get('type')))
    for edge in sorted(edges, key=_edge_key):
        if not edge or not edge.get('source') or not edge.get('target'):
            continue
        if allowed and edge.get('type') not in allowed:
            continue
        s = edge['source']
        t = edge['target']
        if counts.get(s, 0) >= max_edges_per_node or counts.get(t, 0) >= max_edges_per_node:
            continue
        selected.append(edge)
        counts[s] = counts.get(s, 0) + 1
        counts[t] = counts.get(t, 0) + 1
    return selected

def load_all_raw_records():
    """Load all raw threat records from ACE-T intel bundle."""
    raw_records = []

    if not _is_allowed_source('Ransomware.Live'):
        print("Ransomware.Live not in ingest allowlist; skipping all sources.")
        return raw_records

    # Load from ACE-T intel bundle (Tier 4 - excluded)
    if is_tier1_source('ACE-T Intel Bundle'):
        intel_bundle_path = PROJECT_ROOT / 'data' / 'intel_bundle.json'
        if intel_bundle_path.exists():
            try:
                with open(intel_bundle_path, 'r') as f:
                    bundle_data = json.load(f)

                objects = bundle_data.get('objects', [])
                for obj in objects:
                    if obj.get('type') == 'entity':
                        # Extract relevant fields for ransomware analysis
                        name = obj.get('name', '')
                        labels = obj.get('labels', [])
                        tags = obj.get('tags', [])

                        # Check if this is ransomware-related
                        is_ransomware_related = False
                        ransomware_indicators = ['ransomware', 'lockbit', 'conti', 'revil', 'alphv', 'blackcat', 'cl0p']

                        text_to_check = f"{name} {' '.join(labels)} {' '.join(tags)}".lower()
                        if any(indicator in text_to_check for indicator in ransomware_indicators):
                            is_ransomware_related = True

                        if is_ransomware_related:
                            # Extract victim information from name/URL
                            victim_name = None
                            group = None
                            sector = None
                            country = None

                            # Try to extract from URL patterns
                            if 'ransomware' in name.lower():
                                # Parse URLs for victim information
                                if 'mcdonalds' in name.lower():
                                    victim_name = 'McDonalds India'
                                    group = 'Everest'
                                elif 'valley_eye' in name.lower():
                                    victim_name = 'Valley Eye Associates'
                                elif 'ingram_micro' in name.lower():
                                    victim_name = 'Ingram Micro'
                                elif 'everest' in name.lower():
                                    group = 'Everest'
                                # Add more parsing logic as needed

                            # For now, create a record for any ransomware-related entity
                            # Even if we can't extract specific details, we can use the URL/entity name
                            if not victim_name:
                                # Extract victim name from URL or entity name
                                if _is_reddit_reference(name):
                                    # For Reddit URLs, try to extract meaningful title from URL path
                                    parsed_name = urllib.parse.urlparse(name if '://' in name else f'https://{name}')
                                    path_parts = [part for part in parsed_name.path.split('/') if part]
                                    if len(path_parts) >= 4 and path_parts[0].lower() == 'r' and path_parts[2].lower() == 'comments':
                                        title_slug = path_parts[3]
                                        victim_name = title_slug.replace('_', ' ').replace('-', ' ')[:50]
                                    else:
                                        post_token = path_parts[-1] if path_parts else 'unknown'
                                        victim_name = f"Reddit Post {post_token}"
                                else:
                                    victim_name = name[:50]

                            record = {
                                'source': 'ACE-T Intel Bundle',
                                'category': 'ransomware',
                                'title': victim_name,
                                'group': group or 'Unknown',
                                'sector': sector or 'Unknown',
                                'country': country or 'Unknown',
                                'discovered': obj.get('created_at', datetime.now().isoformat()),
                                'description': f"Ransomware-related entity: {name}",
                                'url': name if name.startswith('http') else None
                            }
                            raw_records.append(record)

            except Exception as e:
                print(f"Error loading intel bundle: {e}")

    # Load Ransomware Live victims (rate-limited + cached)
    ransomware_victims = load_ransomware_live_victims()
    ransomware_count = 0
    def _normalize_url(value: str) -> str:
        if not value:
            return ''
        text = str(value).strip()
        if not text:
            return ''
        if text.startswith('http://') or text.startswith('https://'):
            return text
        return f"https://{text}"

    for victim in ransomware_victims:
        if not isinstance(victim, dict):
            continue
        name = (
            victim.get('victim') or victim.get('name') or victim.get('title')
            or victim.get('post_title') or victim.get('website') or 'Unknown victim'
        )
        discovered = victim.get('discovered') or victim.get('date') or victim.get('discovered_at') or victim.get('published')
        country = victim.get('country') or victim.get('country_code') or 'Unknown'
        sector = victim.get('sector') or victim.get('industry') or 'Unknown'
        group = victim.get('group') or victim.get('gang') or victim.get('group_name') or 'Unknown'
        website = victim.get('website') or victim.get('url') or victim.get('link') or victim.get('post_url')
        website = _normalize_url(website)
        source_url = victim.get('permalink') or victim.get('post_url') or website
        source_url = _normalize_url(source_url)
        if name and name != 'Unknown victim' and isinstance(name, str) and name.endswith('.com') and not website:
            website = _normalize_url(name)

        info_parts = [f"Victim: {name}"]
        if group:
            info_parts.append(f"Group: {group}")
        if sector:
            info_parts.append(f"Sector: {sector}")
        if country:
            info_parts.append(f"Country: {country}")
        if discovered:
            info_parts.append(f"Discovered: {discovered}")
        if website:
            info_parts.append(f"URL: {website}")

        description = victim.get('description') or victim.get('summary') or 'Ransomware victim listing'
        if isinstance(description, str) and description.strip().lower() in {'n/a', 'na', 'unknown', 'unknown victim'}:
            description = 'Ransomware victim listing'
        if isinstance(description, str) and description.strip().lower().startswith('[ai generated]'):
            cleaned = description.replace('[AI generated]', '').strip().strip('"').strip()
            if cleaned:
                description = cleaned
            else:
                description = 'Ransomware victim listing'

        category_hint = victim.get('victim_category') or victim.get('ace_category')
        derived_sector = _classify_victim_category(name, description, sector, website)
        if category_hint:
            sector = category_hint
        elif derived_sector != 'Unknown':
            sector = derived_sector

        raw_records.append({
            'source': 'Ransomware.Live',
            'category': 'ransomware',
            'predicted_label': 'ransomware',
            'predicted_prob': 0.55,
            'description': description,
            'title': name,
            'url': website,
            'group': group,
            'sector': sector,
            'country': country,
            'discovered': discovered,
            'notes': ' | '.join(info_parts),
            'reporting_source': 'Ransomware.Live victim search',
            'source_url': source_url,
            'subsource': 'victim_search'
        })
        ransomware_count += 1

    if ransomware_count:
        print(f"Loaded {ransomware_count} ransomware live victims")
    print(f"After ransomware live: {len(raw_records)} records")

    # Load NADW scored data (prioritize selected categories) - DISABLED: Focus on real ACE-T data only
    # scored_csv_path = PROJECT_ROOT / 'outputs/scored/scored.csv'
    # if scored_csv_path.exists():
    #     ... (NADW CSV loading code removed to focus on real threat data)
    print(f"After NADW (disabled): {len(raw_records)} records")

    # Load live threat data (Tier 4 - excluded)
    if is_tier1_source('Live'):
        live_scores_path = PROJECT_ROOT / 'nadw-osint-scoring/outputs/scored/live_scores.jsonl'
        if live_scores_path.exists():
            live_count = 0
            with open(live_scores_path, 'r') as f:
                for line in f:
                    if line.strip():
                        data = json.loads(line.strip())
                        raw_records.append({
                            'source': 'Live',
                            'predicted_label': data.get('prediction', 'Unknown'),
                            'predicted_prob': float(data.get('confidence', 0.5)),
                            'ip': data.get('features', {}).get('src_ip', ''),
                            'dst_ip': data.get('features', {}).get('dst_ip', ''),
                            'protocol': data.get('features', {}).get('protocol', ''),
                            'dst_port': data.get('features', {}).get('dst_port', ''),
                            'threat': data.get('features', {}).get('threat', ''),
                            'received_at': data.get('features', {}).get('received_at', ''),
                            'timestamp': data.get('timestamp', ''),
                            'reporting_source': 'Live Threat Monitoring'
                        })
                        live_count += 1
            print(f"Loaded {live_count} live records")
    print(f"After live: {len(raw_records)} records")

    before_filter = len(raw_records)
    raw_records = [record for record in raw_records if not is_older_than_days(record, 30)]
    filtered = before_filter - len(raw_records)
    if filtered:
        print(f"Filtered {filtered} records older than 30 days")

    # Enforce ingest allowlist
    raw_records = [
        record for record in raw_records
        if _is_allowed_source(record.get('source', ''))
    ]

    # Load original SPECTRUM graph data
    original_graph_path = PROJECT_ROOT / 'clean_project' / 'data' / 'graph_3d.json'
    if original_graph_path.exists() and _is_allowed_source('Original SPECTRUM Graph'):
        try:
            with open(original_graph_path, 'r') as f:
                original_data = json.load(f)

            nodes = original_data.get('nodes', [])
            for node in nodes:
                if EXCLUDE_REDDIT:
                    if (
                        _is_reddit_reference(node.get('source_url', ''))
                        or _is_reddit_reference(node.get('label', ''))
                        or _is_reddit_reference(node.get('source', ''))
                    ):
                        continue
                # Convert original SPECTRUM format to our record format
                record = {
                    'source': 'Original SPECTRUM Graph',
                    'category': node.get('kind', 'entity'),
                    'title': node.get('label', 'Unknown'),
                    'group': node.get('band', 'Unknown'),
                    'sector': node.get('subsource', 'Unknown'),
                    'country': 'Unknown',  # Original data doesn't have country
                    'discovered': datetime.fromtimestamp(node.get('timestamp', 0)).isoformat() if node.get('timestamp') else datetime.now().isoformat(),
                    'description': f"Original SPECTRUM entity: {node.get('label', 'Unknown')}",
                    'url': node.get('source_url'),
                    'spectrum_data': node  # Keep original spectrum properties
                }
                raw_records.append(record)

            print(f"Loaded {len(nodes)} nodes from original SPECTRUM graph")
        except Exception as e:
            print(f"Error loading original graph data: {e}")

    # Load Twitter threat data
    twitter_records = load_twitter_threats()
    raw_records.extend(twitter_records)
    if twitter_records:
        print(f"Loaded {len(twitter_records)} Twitter threat records")

    # Load ThreatFox data
    threatfox_records = load_threatfox()
    raw_records.extend(threatfox_records)
    if threatfox_records:
        print(f"Loaded {len(threatfox_records)} ThreatFox records")

    # Load URLhaus data
    urlhaus_records = load_urlhaus()
    raw_records.extend(urlhaus_records)
    if urlhaus_records:
        print(f"Loaded {len(urlhaus_records)} URLhaus records")

    _normalize_records(raw_records)
    print(f"Total raw records: {len(raw_records)}")
    _log_source_summary(raw_records, "Source summary")
    return raw_records

def calculate_duration(first_seen: str, last_seen: str) -> str:
    """Calculate duration between first and last seen."""
    try:
        first_dt = datetime.fromisoformat(first_seen.replace('Z', '+00:00'))
        last_dt = datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
        delta = last_dt - first_dt

        if delta.days > 0:
            return f"{delta.days} days"
        elif delta.seconds > 3600:
            return f"{delta.seconds // 3600} hours"
        elif delta.seconds > 60:
            return f"{delta.seconds // 60} minutes"
        else:
            return f"{delta.seconds} seconds"
    except:
        return "Unknown"

def get_affected_description(threat: dict) -> str:
    """Get affected systems description."""
    indicators = threat.get('indicators', {})

    if indicators.get('ip'):
        return f"IP: {indicators['ip']}"
    elif indicators.get('domain'):
        return f"Domain: {indicators['domain']}"
    elif indicators.get('url'):
        return "Web resources"
    elif indicators.get('email'):
        return "Email systems"
    else:
        return "Various systems"

def get_description(threat: dict) -> str:
    """Get threat description."""
    metadata = threat.get('metadata', {})
    indicators = threat.get('indicators', {})

    if metadata.get('description'):
        return metadata['description']
    elif indicators.get('malware'):
        return f"Malware detected: {indicators['malware']}"
    elif indicators.get('actor'):
        return f"Threat actor activity: {indicators['actor']}"
    else:
        return f"{threat.get('category', 'Unknown')} threat detected"

def get_known_info(threat: dict) -> str:
    """Get known information about the threat."""
    metadata = threat.get('metadata', {})
    indicators = threat.get('indicators', {})

    info_parts = []

    if metadata.get('description'):
        info_parts.append(metadata['description'])

    if indicators.get('malware'):
        info_parts.append(f"Associated malware: {indicators['malware']}")

    if indicators.get('actor'):
        info_parts.append(f"Associated actor: {indicators['actor']}")

    if threat.get('record_count', 1) > 1:
        info_parts.append(f"Observed {threat['record_count']} times")

    lifecycle = threat.get('lifecycle_stage', 'unknown')
    info_parts.append(f"Current status: {lifecycle}")

    return '. '.join(info_parts) if info_parts else "Limited information available"

def create_spectrum_edges(nodes: list) -> list:
    """Create deterministic edges between ransomware incident nodes according to SPECTRUM directive."""
    # PHASE 0 — GRAPH SANITIZATION (MANDATORY)
    # Start with empty edges and valid node IDs only.
    valid_nodes = [n for n in nodes if isinstance(n, dict) and n.get('id')]
    nodes_by_id = {n['id']: n for n in valid_nodes}
    ordered_nodes = sorted(valid_nodes, key=lambda n: str(n.get('id')))

    edges = []
    seen_edges = set()
    cross_group_edges = {}
    domain_edges = {}

    def _edge_key(a, b, edge_type):
        # ensure deterministic undirected key
        left, right = (a, b) if str(a) <= str(b) else (b, a)
        return (left, right, edge_type)

    def _can_add(source, target, edge_type):
        if source == target:
            return False
        if source not in nodes_by_id or target not in nodes_by_id:
            return False
        if edge_type == 'CROSS_GROUP_SECTOR':
            if cross_group_edges.get(source, 0) >= 3 or cross_group_edges.get(target, 0) >= 3:
                return False
        if edge_type == 'DOMAIN_PATTERN_MATCH':
            if domain_edges.get(source, 0) >= 2 or domain_edges.get(target, 0) >= 2:
                return False
        key = _edge_key(source, target, edge_type)
        if key in seen_edges:
            return False
        return True

    def _add_edge(source, target, edge_type, weight):
        if not _can_add(source, target, edge_type):
            return False
        edges.append({
            'source': source,
            'target': target,
            'type': edge_type,
            'weight': weight
        })
        seen_edges.add(_edge_key(source, target, edge_type))
        if edge_type == 'CROSS_GROUP_SECTOR':
            cross_group_edges[source] = cross_group_edges.get(source, 0) + 1
            cross_group_edges[target] = cross_group_edges.get(target, 0) + 1
        if edge_type == 'DOMAIN_PATTERN_MATCH':
            domain_edges[source] = domain_edges.get(source, 0) + 1
            domain_edges[target] = domain_edges.get(target, 0) + 1
        return True

    def _parse_first_observed(node):
        return _parse_datetime(node.get('first_observed') or node.get('last_observed'))

    def _time_delta_seconds(a, b):
        ta = _parse_first_observed(a)
        tb = _parse_first_observed(b)
        if not ta or not tb:
            return None
        return abs((ta - tb).total_seconds())

    # PHASE 1 — HARD ASSOCIATIONS (MANDATORY)
    group_nodes = {}
    for node in ordered_nodes:
        group = node.get('group')
        if group:
            group_nodes.setdefault(group, []).append(node)

    group_anchors = {}
    for group, members in group_nodes.items():
        def _anchor_key(n):
            ts = _parse_first_observed(n)
            return (ts.timestamp() if ts else float('inf'), str(n.get('id')))
        group_anchors[group] = sorted(members, key=_anchor_key)[0]

    for group, members in group_nodes.items():
        anchor = group_anchors[group]
        for node in members:
            if node['id'] == anchor['id']:
                continue
            _add_edge(anchor['id'], node['id'], 'SAME_GROUP', 5)

    for i, node_a in enumerate(ordered_nodes):
        for node_b in ordered_nodes[i + 1:]:
            if (node_a.get('group') and node_b.get('group') and
                node_a.get('sector') and node_b.get('sector') and
                node_a['group'] == node_b['group'] and
                node_a['sector'] == node_b['sector']):
                _add_edge(node_a['id'], node_b['id'], 'GROUP_SECTOR_OVERLAP', 3)

    for i, node_a in enumerate(ordered_nodes):
        for node_b in ordered_nodes[i + 1:]:
            if (node_a.get('group') and node_b.get('group') and
                node_a.get('country') and node_b.get('country') and
                node_a['group'] == node_b['group'] and
                node_a['country'] == node_b['country']):
                _add_edge(node_a['id'], node_b['id'], 'GROUP_COUNTRY_OVERLAP', 2)

    # PHASE 2 — CONTROLLED CROSS-GROUP ASSOCIATIONS
    sector_groups = {}
    for node in ordered_nodes:
        sector = node.get('sector')
        if sector:
            sector_groups.setdefault(sector, []).append(node)

    for sector_nodes in sector_groups.values():
        if len(sector_nodes) < 2:
            continue
        sector_nodes_sorted = sorted(sector_nodes, key=lambda n: str(n.get('id')))
        for node in sector_nodes_sorted:
            if cross_group_edges.get(node['id'], 0) >= 3:
                continue
            candidates = []
            for other in sector_nodes_sorted:
                if other['id'] == node['id']:
                    continue
                if node.get('group') == other.get('group'):
                    continue
                delta = _time_delta_seconds(node, other)
                delta_key = delta if delta is not None else float('inf')
                candidates.append((delta_key, str(other['id']), other))
            candidates.sort(key=lambda x: (x[0], x[1]))
            for _, __, other in candidates:
                if cross_group_edges.get(node['id'], 0) >= 3:
                    break
                _add_edge(node['id'], other['id'], 'CROSS_GROUP_SECTOR', 1)

    # PHASE 3 — DOMAIN & VICTIM PATTERN ASSOCIATION
    provider_tokens = {
        'cloudflare', 'aws', 'amazon', 'azure', 'microsoft', 'google', 'akamai',
        'fastly', 'cloudfront', 'digitalocean', 'ovh', 'linode', 'github', 'gitlab'
    }
    host_tokens = {'www', 'mail', 'smtp', 'imap', 'pop', 'api', 'cdn', 'static', 'img'}
    common_suffixes = {'co', 'com', 'org', 'net', 'gov', 'edu'}

    def _normalize_domain(raw):
        if not raw:
            return None
        text = str(raw).strip().lower()
        if '://' in text:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(text)
                text = parsed.netloc or parsed.path
            except Exception:
                pass
        if ':' in text:
            text = text.split(':', 1)[0]
        if text.startswith('www.'):
            text = text[4:]
        return text or None

    def _root_domain(domain):
        if not domain or '.' not in domain:
            return domain
        parts = [p for p in domain.split('.') if p]
        if len(parts) <= 2:
            return '.'.join(parts)
        tld = parts[-1]
        sld = parts[-2]
        if tld and len(tld) == 2 and sld in common_suffixes and len(parts) >= 3:
            return '.'.join(parts[-3:])
        return '.'.join(parts[-2:])

    def _stem_tokens(domain):
        if not domain:
            return set()
        root = _root_domain(domain) or domain
        base = root.split('.')
        tokens = []
        for part in base:
            tokens.extend(part.replace('-', ' ').split())
        stems = set()
        for token in tokens:
            token = token.strip()
            if not token or token in host_tokens:
                continue
            if token.isdigit():
                continue
            if len(token) < 4:
                continue
            stems.add(token)
        return stems

    nodes_with_domains = [n for n in ordered_nodes if n.get('victim_domain')]
    for i, node_a in enumerate(nodes_with_domains):
        for node_b in nodes_with_domains[i + 1:]:
            if domain_edges.get(node_a['id'], 0) >= 2 and domain_edges.get(node_b['id'], 0) >= 2:
                continue
            domain_a = _normalize_domain(node_a.get('victim_domain'))
            domain_b = _normalize_domain(node_b.get('victim_domain'))
            if not domain_a or not domain_b:
                continue
            root_a = _root_domain(domain_a)
            root_b = _root_domain(domain_b)
            if root_a and root_b and root_a == root_b:
                _add_edge(node_a['id'], node_b['id'], 'DOMAIN_PATTERN_MATCH', 4)
                continue
            stems_a = _stem_tokens(domain_a)
            stems_b = _stem_tokens(domain_b)
            overlap = stems_a.intersection(stems_b)
            if overlap:
                if overlap.issubset(provider_tokens):
                    continue
                _add_edge(node_a['id'], node_b['id'], 'DOMAIN_PATTERN_MATCH', 4)

    # PHASE 4 — TEMPORAL CAMPAIGN CLUSTERING
    for i, node_a in enumerate(ordered_nodes):
        for node_b in ordered_nodes[i + 1:]:
            if node_a.get('group') != node_b.get('group'):
                continue
            delta = _time_delta_seconds(node_a, node_b)
            if delta is None:
                continue
            if delta <= 3600:
                _add_edge(node_a['id'], node_b['id'], 'TIME_CLUSTER', 3)

    # FAILSAFE - Connect orphaned nodes to nearest SAME_GROUP node by time
    nodes_with_edges = set()
    for edge in edges:
        nodes_with_edges.add(edge['source'])
        nodes_with_edges.add(edge['target'])

    orphaned_nodes = [n for n in ordered_nodes if n['id'] not in nodes_with_edges]
    for orphan in orphaned_nodes:
        orphan_group = orphan.get('group')
        if not orphan_group:
            continue
        same_group_nodes = [n for n in ordered_nodes if n.get('group') == orphan_group and n['id'] != orphan['id']]
        if not same_group_nodes:
            continue
        candidates = []
        for other in same_group_nodes:
            delta = _time_delta_seconds(orphan, other)
            delta_key = delta if delta is not None else float('inf')
            candidates.append((delta_key, str(other['id']), other))
        candidates.sort(key=lambda x: (x[0], x[1]))
        for _, __, other in candidates:
            if _add_edge(orphan['id'], other['id'], 'SAME_GROUP', 1):
                break

    return edges

def build_graph():
    """Build the graph data in batch mode."""
    graph_path = BASE_DIR / 'graph_3d.json'
    last_count_file = BASE_DIR / 'last_live_count.txt'
    prior_state_file = BASE_DIR / 'threat_state.json'

    # Read previous live count
    last_count = 0
    if last_count_file.exists():
        try:
            with open(last_count_file, 'r') as f:
                last_count = int(f.read().strip())
        except:
            last_count = 0

    # Load prior state if exists (filter out OSINT datasets)
    prior_state = {'threats': [], 'index': {'fingerprint_to_threat_id': {}}}
    if prior_state_file.exists():
        try:
            with open(prior_state_file, 'r') as f:
                prior_state = json.load(f)
        except:
            pass
    prior_state = sanitize_prior_state(prior_state)

    # Collect all raw records
    raw_records = load_all_raw_records()
    total_records = len(raw_records)

    # Count current live threats
    current_live_count = sum(1 for r in raw_records if r.get('source') == 'Live')

    # If new live alerts, play tone
    if current_live_count > last_count:
        try:
            os.system('afplay /System/Library/Sounds/Ping.aiff')
        except:
            pass

    # Filter for threat incidents (Tier 1 only + original SPECTRUM baseline)
    threat_records = []
    for r in raw_records:
        source = r.get('source', '')
        # Always include original SPECTRUM data
        if source == 'Original SPECTRUM Graph':
            threat_records.append(r)
            continue
        if not is_tier1_source(source):
            continue
        # For Tier 1 sources, check if they're ransomware-related when applicable
        threat_dict = {
            'category': r.get('category', ''),
            'indicators': {'group': r.get('group', ''), 'malware': r.get('group', '')},
            'metadata': r
        }
        if (is_ransomware_threat(threat_dict) or 
            source.lower() == 'ransomware.live' or 
            source.lower() == 'abuse.ch threatfox' or
            source.lower() == 'abuse.ch urlhaus'):
            threat_records.append(r)

    total_threats = len(threat_records)

    if total_threats == 0:
        graph_data = {
            'nodes': [],
            'edges': [],
            'metadata': {
                'total_threats': 0,
                'processed_records': total_records,
                'threat_incidents': 0,
                'generated_at': datetime.now().isoformat() + 'Z',
                'batch_info': 'No threat incidents to process'
            }
        }
        _atomic_write_json(graph_path, graph_data)
        return graph_data

    # Create nodes for threat incidents according to SPECTRUM node contract
    nodes = []
    for i, record in enumerate(threat_records):
        # Handle original SPECTRUM data differently - preserve existing properties
        if record.get('source') == 'Original SPECTRUM Graph' and 'spectrum_data' in record:
            spectrum_node = record['spectrum_data']
            spectrum_source_url = spectrum_node.get('source_url') or ''
            spectrum_source = _derive_source_from_url(spectrum_source_url, spectrum_node.get('source'))
            # Convert to our SPECTRUM contract format but preserve coordinates and spectrum properties
            node = {
                'id': spectrum_node.get('id', f"spectrum_{i}"),
                'label': spectrum_node.get('label', 'Unknown'),
                'kind': spectrum_node.get('kind', spectrum_node.get('type', 'entity')),
                'victim_name': spectrum_node.get('label', 'Unknown'),
                'victim_domain': None,
                'group': spectrum_node.get('band', 'Unknown'),
                'sector': spectrum_node.get('subsource', 'Unknown'),
                'country': 'Unknown',
                'source': spectrum_source,
                'source_key': spectrum_node.get('subsource') or spectrum_source,
                'subsource': spectrum_node.get('subsource', ''),
                'source_url': spectrum_node.get('source_url'),
                'first_observed': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else datetime.now().isoformat(),
                'last_observed': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else datetime.now().isoformat(),
                'description': f"Original SPECTRUM: {spectrum_node.get('label', 'Unknown')}",
                'posted_at': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                'last_activity': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                # Preserve original spectrum properties
                'x': spectrum_node.get('x'),
                'y': spectrum_node.get('y'),
                'z': spectrum_node.get('z', spectrum_node.get('z_position')),
                'color': spectrum_node.get('color', spectrum_node.get('spectral_color')),
                'size': spectrum_node.get('size'),
                'opacity': spectrum_node.get('opacity'),
                'band': spectrum_node.get('band'),
                'confidence': spectrum_node.get('confidence'),
                'severity': spectrum_node.get('severity'),
                'spectrum_band_weight': spectrum_node.get('spectrum_band_weight'),
                'spectrum_index': spectrum_node.get('spectrum_index'),
                'convergence': spectrum_node.get('convergence'),
                'mass': spectrum_node.get('mass'),
                'degree': spectrum_node.get('degree'),
                'temporal_alignment': spectrum_node.get('temporal_alignment'),
                'indicator_convergence': spectrum_node.get('indicator_convergence'),
                'cross_source_degree': spectrum_node.get('cross_source_degree'),
                'same_source_degree': spectrum_node.get('same_source_degree'),
                'signal_density': spectrum_node.get('signal_density'),
                'band_weight': spectrum_node.get('band_weight'),
                'volume_count': spectrum_node.get('volume_count'),
                'volume_weight': spectrum_node.get('volume_weight'),
                'energy_weight': spectrum_node.get('energy_weight'),
                'source_color': spectrum_node.get('source_color'),
                'spectrum_color': spectrum_node.get('spectrum_color'),
                'recency': spectrum_node.get('recency'),
                'adjusted_confidence': spectrum_node.get('adjusted_confidence'),
                'domain_convergence_score': spectrum_node.get('domain_convergence_score')
            }
            nodes.append(node)
            continue

        # Generate unique ID for new records
        victim_name = record.get('title') or record.get('victim') or record.get('name') or f'Unknown_{i}'
        group = record.get('group') or 'Unknown'
        sector = record.get('sector') or 'Unknown'
        country = record.get('country') or 'Unknown'
        source = record.get('source') or 'Unknown'
        first_observed = record.get('discovered') or record.get('first_seen') or record.get('timestamp') or datetime.now().isoformat()
        last_observed = record.get('last_seen') or first_observed
        description = record.get('description') or record.get('notes') or 'Ransomware victim listing'
        if isinstance(description, str) and description.strip().lower() in {'n/a', 'na', 'unknown', 'unknown victim'}:
            description = 'Ransomware victim listing'

        # Extract victim_domain if available (from website/url)
        victim_domain = None
        website = record.get('url') or record.get('website') or record.get('link') or record.get('source_url')
        if website:
            candidate_domain = _extract_domain(website)
            if candidate_domain and not _is_same_or_subdomain(candidate_domain, 'reddit.com'):
                victim_domain = candidate_domain

        label_value = victim_name
        if (not label_value or label_value.lower() in {'unknown', 'unknown victim'}) and victim_domain:
            label_value = victim_domain

        subsource = record.get('subsource') or record.get('reporting_source') or ''
        source_url = record.get('source_url') or website or ''
        if source_url and not source_url.startswith('http'):
            source_url = f"https://{source_url}"
        law_match = str(sector or '').strip().lower() == 'law'
        if description == 'Ransomware victim listing' and victim_name:
            description = victim_name
        severity = record.get('severity') or record.get('impact') or ('high' if _normalize_source_name(source) == 'ransomware.live' else 'unknown')
        node_id = f"{group}_{victim_name}_{i}".replace(' ', '_').replace('/', '_')
        if _is_threatfox_source(source):
            indicator = record.get('ioc_value') or record.get('title') or record.get('victim') or victim_name
            ioc_kind = record.get('ioc_type') or record.get('subsource') or ''
            node_id = f"tf_{hashlib.sha1(f'{indicator}|{ioc_kind}'.encode('utf-8', 'ignore')).hexdigest()[:16]}"

        node = {
            'id': node_id,
            'label': label_value,
            'kind': record.get('category') or 'ransomware',
            'victim_name': victim_name,
            'victim_domain': victim_domain,
            'group': group,
            'sector': sector or 'Unknown',
            'country': country or 'Unknown',
            'source': _normalize_source_name(source),
            'source_key': _normalize_source_name(source),
            'subsource': subsource,
            'source_url': source_url,
            'first_observed': first_observed,
            'last_observed': last_observed,
            'description': description,
            'confidence': record.get('predicted_prob') if record.get('predicted_prob') is not None else record.get('confidence'),
            'severity': severity,
            'posted_at': record.get('discovered') or record.get('timestamp') or first_observed,
            'last_activity': record.get('last_seen') or record.get('last_observed') or record.get('updated_at') or last_observed,
            'spectrum_color': '#ff1a1a' if law_match else None,
            'source_color': '#ff1a1a' if law_match else None
        }
        if _is_threatfox_source(source):
            node['ioc_type'] = record.get('ioc_type') or record.get('subsource')
            node['ioc_value'] = record.get('ioc_value') or record.get('title') or record.get('victim')
            node['tags'] = record.get('tags') or []
            node['malware'] = record.get('malware') or record.get('group')
            node['node_color'] = '#39ff14'
            node['glow_color'] = '#39ff14'
            node['source_color'] = '#39ff14'
        elif _normalize_source_name(source) == 'abuse.ch urlhaus':
            node['ioc_type'] = record.get('ioc_type') or 'url'
            node['ioc_value'] = record.get('ioc_value') or record.get('url') or record.get('title')
            node['tags'] = record.get('tags') or []
            node['malware'] = record.get('threat') or record.get('group')
            urlhaus_color = _category_color_for('URLhaus')
            if urlhaus_color:
                node['source_color'] = urlhaus_color
        elif _normalize_source_name(source) == 'ransomware.live':
            node['source_color'] = '#ff3333'
        nodes.append(node)

    # Normalize colors and coordinates for all nodes
    for node in nodes:
        if not isinstance(node, dict):
            continue
        sector_val = node.get('sector') or node.get('victim_category') or node.get('category')
        category_color = _category_color_for(sector_val)
        if category_color:
            node['spectrum_color'] = category_color
            if not node.get('source_color'):
                node['source_color'] = category_color

        def _needs_coord(value):
            if value is None:
                return True
            try:
                float(value)
            except Exception:
                return True
            return False

        if _needs_coord(node.get('x')) or _needs_coord(node.get('y')):
            seed = node.get('id') or node.get('label') or node.get('victim_name') or ''
            r1 = _stable_rng(f"{seed}-a")
            r2 = _stable_rng(f"{seed}-b")
            r3 = _stable_rng(f"{seed}-c")
            angle = r1 * math.tau
            radius = 120 + (r2 * 180)
            z_offset = (r3 - 0.5) * 140
            node['x'] = round(radius * math.cos(angle), 3)
            node['y'] = round(radius * math.sin(angle), 3)
            if _needs_coord(node.get('z')):
                node['z'] = round(z_offset, 3)
            else:
                try:
                    node['z'] = round(float(node.get('z')) + z_offset, 3)
                except Exception:
                    node['z'] = round(z_offset, 3)

    layout_meta = _apply_threatfox_layout(nodes)
    _apply_urlhaus_layout(nodes)

    # Enforce allowlist + reddit suppression at node layer
    filtered_nodes = []
    for node in nodes:
        if node.get('is_cluster'):
            filtered_nodes.append(node)
            continue
        if not _is_allowed_source(node.get('source', '')):
            continue
        if EXCLUDE_REDDIT:
            if (
                _is_reddit_reference(node.get('source_url', ''))
                or _is_reddit_reference(node.get('label', ''))
                or _is_reddit_reference(node.get('source', ''))
            ):
                continue
        filtered_nodes.append(node)
    nodes = filtered_nodes

    # Create deterministic edges according to SPECTRUM directive
    edge_nodes = [n for n in nodes if not n.get('is_cluster')]
    edges = create_spectrum_edges(edge_nodes)

    render_edges = _build_render_edges(edges, max_edges_per_node=6)
    graph_edges = edges if WRITE_FULL_GRAPH else render_edges
    graph_data = {
        'nodes': nodes,
        'edges': graph_edges,
        'metadata': {
            'total_threats': len(nodes),
            'processed_records': total_records,
            'threat_incidents': total_threats,
            'generated_at': datetime.now().isoformat() + 'Z',
            'batch_info': f"SPECTRUM graph: {len(nodes)} nodes, {len(edges)} edges from ACE-T, Original SPECTRUM, and Twitter data",
            'full_edge_count': len(edges),
            'render_edge_count': len(render_edges),
            'full_graph_written': WRITE_FULL_GRAPH,
            'clusters': layout_meta.get('clusters', []) if isinstance(layout_meta, dict) else []
        }
    }
    render_graph = {
        'nodes': nodes,
        'edges': render_edges,
        'metadata': {
            'total_threats': len(nodes),
            'processed_records': total_records,
            'threat_incidents': total_threats,
            'generated_at': graph_data['metadata']['generated_at'],
            'render_edges': len(render_edges),
            'total_edges': len(edges),
            'batch_info': 'SPECTRUM render graph',
            'clusters': layout_meta.get('clusters', []) if isinstance(layout_meta, dict) else []
        }
    }
    _write_sources_json(nodes)

    _atomic_write_json(graph_path, graph_data)
    render_path = BASE_DIR / 'graph_3d_render.json'
    _atomic_write_json(render_path, render_graph)

    return graph_data

def build_graph_streaming(batch_size=1, delay_between_batches=0.5, poll_interval=2.0):
    """Build the graph data in streaming mode - append new threats one at a time."""
    import time

    print("Starting streaming graph build...")
    graph_path = BASE_DIR / 'graph_3d.json'

    if not graph_path.exists():
        empty_graph = {
            'nodes': [],
            'edges': [],
            'metadata': {
                'total_threats': 0,
                'processed_records': 0,
                'ransomware_incidents': 0,
                'generated_at': datetime.now().isoformat() + 'Z',
                'batch_info': 'Initializing streaming build...'
            }
        }
        _atomic_write_json(graph_path, empty_graph)

    # Read previous live count
    last_count_file = BASE_DIR / 'last_live_count.txt'
    last_count = 0
    if last_count_file.exists():
        try:
            with open(last_count_file, 'r') as f:
                last_count = int(f.read().strip())
        except:
            last_count = 0

    while True:
        # Load all raw records using SPECTRUM approach
        raw_records = load_all_raw_records()
        total_records = len(raw_records)

        current_live_count = sum(1 for r in raw_records if r.get('source') == 'Live')
        if current_live_count > last_count:
            try:
                os.system('afplay /System/Library/Sounds/Ping.aiff')
            except:
                pass
            last_count = current_live_count

        # Filter for threat incidents (Tier 1 only + original SPECTRUM baseline)
        threat_records = []
        for r in raw_records:
            source = r.get('source', '')
            # Always include original SPECTRUM data
            if source == 'Original SPECTRUM Graph':
                threat_records.append(r)
                continue
            if not is_tier1_source(source):
                continue
            threat_dict = {
                'category': r.get('category', ''),
                'indicators': {'group': r.get('group', ''), 'malware': r.get('group', '')},
                'metadata': r
            }
            if is_ransomware_threat(threat_dict) or source.lower() == 'ransomware.live':
                threat_records.append(r)

        # Create nodes for threat incidents according to SPECTRUM node contract
        nodes = []
        for i, record in enumerate(threat_records):
            # Handle original SPECTRUM data differently - preserve existing properties
            if record.get('source') == 'Original SPECTRUM Graph' and 'spectrum_data' in record:
                spectrum_node = record['spectrum_data']
                spectrum_source_url = spectrum_node.get('source_url') or ''
                spectrum_source = _derive_source_from_url(spectrum_source_url, spectrum_node.get('source'))
                # Convert to our SPECTRUM contract format but preserve coordinates and spectrum properties
                node = {
                    'id': spectrum_node.get('id', f"spectrum_{i}"),
                    'label': spectrum_node.get('label', 'Unknown'),
                    'kind': spectrum_node.get('kind', spectrum_node.get('type', 'entity')),
                    'victim_name': spectrum_node.get('label', 'Unknown'),
                    'victim_domain': None,
                    'group': spectrum_node.get('band', 'Unknown'),
                    'sector': spectrum_node.get('subsource', 'Unknown'),
                    'country': 'Unknown',
                    'source': spectrum_source,
                    'source_key': spectrum_node.get('subsource') or spectrum_source,
                    'subsource': spectrum_node.get('subsource', ''),
                    'source_url': spectrum_node.get('source_url'),
                    'first_observed': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else datetime.now().isoformat(),
                    'last_observed': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else datetime.now().isoformat(),
                    'description': f"Original SPECTRUM: {spectrum_node.get('label', 'Unknown')}",
                    'posted_at': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                    'last_activity': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                    'posted_at': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                    'last_activity': datetime.fromtimestamp(spectrum_node.get('timestamp', 0)).isoformat() if spectrum_node.get('timestamp') else None,
                    # Preserve original spectrum properties
                    'x': spectrum_node.get('x'),
                    'y': spectrum_node.get('y'),
                    'z': spectrum_node.get('z', spectrum_node.get('z_position')),
                    'color': spectrum_node.get('color', spectrum_node.get('spectral_color')),
                    'size': spectrum_node.get('size'),
                    'opacity': spectrum_node.get('opacity'),
                    'band': spectrum_node.get('band'),
                    'confidence': spectrum_node.get('confidence'),
                    'severity': spectrum_node.get('severity'),
                    'spectrum_band_weight': spectrum_node.get('spectrum_band_weight'),
                    'spectrum_index': spectrum_node.get('spectrum_index'),
                    'convergence': spectrum_node.get('convergence'),
                    'mass': spectrum_node.get('mass'),
                    'degree': spectrum_node.get('degree'),
                    'temporal_alignment': spectrum_node.get('temporal_alignment'),
                    'indicator_convergence': spectrum_node.get('indicator_convergence'),
                    'cross_source_degree': spectrum_node.get('cross_source_degree'),
                    'same_source_degree': spectrum_node.get('same_source_degree'),
                    'signal_density': spectrum_node.get('signal_density'),
                    'band_weight': spectrum_node.get('band_weight'),
                    'volume_count': spectrum_node.get('volume_count'),
                    'volume_weight': spectrum_node.get('volume_weight'),
                    'energy_weight': spectrum_node.get('energy_weight'),
                    'source_color': spectrum_node.get('source_color'),
                    'spectrum_color': spectrum_node.get('spectrum_color'),
                    'recency': spectrum_node.get('recency'),
                    'adjusted_confidence': spectrum_node.get('adjusted_confidence'),
                    'domain_convergence_score': spectrum_node.get('domain_convergence_score')
                }
                nodes.append(node)
                continue

            # Generate unique ID for new records
            victim_name = record.get('title') or record.get('victim') or record.get('name') or f'Unknown_{i}'
            group = record.get('group') or 'Unknown'
            sector = record.get('sector') or 'Unknown'
            country = record.get('country') or 'Unknown'
            source = record.get('source') or 'Unknown'
            first_observed = record.get('discovered') or record.get('first_seen') or record.get('timestamp') or datetime.now().isoformat()
            last_observed = record.get('last_seen') or first_observed
            description = record.get('description') or record.get('notes') or ''

            # Extract victim_domain if available (from website/url)
            victim_domain = None
            website = record.get('url') or record.get('website') or record.get('link')
            if website:
                candidate_domain = _extract_domain(website)
                if candidate_domain and not _is_same_or_subdomain(candidate_domain, 'reddit.com'):
                    victim_domain = candidate_domain

            label_value = victim_name
            if (not label_value or label_value.lower() in {'unknown', 'unknown victim'}) and victim_domain:
                label_value = victim_domain

            node = {
                'id': f"{group}_{victim_name}_{i}".replace(' ', '_').replace('/', '_'),
                'label': label_value,
                'kind': record.get('category') or 'ransomware_incident',
                'victim_name': victim_name,
                'victim_domain': victim_domain,
                'group': group,
                'sector': sector,
                'country': country,
                'source': _normalize_source_name(source),
                'source_key': _normalize_source_name(source),
                'subsource': record.get('subsource', ''),
                'source_url': website,
                'first_observed': first_observed,
                'last_observed': last_observed,
                'description': description,
                'confidence': record.get('predicted_prob') if record.get('predicted_prob') is not None else record.get('confidence'),
                'severity': record.get('severity') or record.get('impact'),
                'posted_at': record.get('discovered') or record.get('timestamp'),
                'last_activity': record.get('last_seen') or record.get('last_observed') or record.get('updated_at')
            }
            nodes.append(node)

        # Enforce allowlist + reddit suppression at node layer
        filtered_nodes = []
        for node in nodes:
            if not _is_allowed_source(node.get('source', '')):
                continue
            if EXCLUDE_REDDIT:
                if (
                    _is_reddit_reference(node.get('source_url', ''))
                    or _is_reddit_reference(node.get('label', ''))
                    or _is_reddit_reference(node.get('source', ''))
                ):
                    continue
            filtered_nodes.append(node)
        nodes = filtered_nodes

        # Create deterministic edges according to SPECTRUM directive
        edges = create_spectrum_edges(nodes)

        render_edges = _build_render_edges(edges, max_edges_per_node=6)
        graph_edges = edges if WRITE_FULL_GRAPH else render_edges
        graph_data = {
            'nodes': nodes,
            'edges': graph_edges,
            'metadata': {
                'total_threats': len(nodes),
                'processed_records': total_records,
                'threat_incidents': len(threat_records),
                'generated_at': datetime.now().isoformat() + 'Z',
                'batch_info': f"SPECTRUM streaming graph: {len(nodes)} nodes, {len(edges)} edges from ACE-T, Original SPECTRUM, and Twitter data",
                'full_edge_count': len(edges),
                'render_edge_count': len(render_edges),
                'full_graph_written': WRITE_FULL_GRAPH,
            }
        }
        render_graph = {
            'nodes': nodes,
            'edges': render_edges,
            'metadata': {
                'total_threats': len(nodes),
                'processed_records': total_records,
                'threat_incidents': len(threat_records),
                'generated_at': graph_data['metadata']['generated_at'],
                'render_edges': len(render_edges),
                'total_edges': len(edges),
                'batch_info': 'SPECTRUM streaming render graph'
            }
        }
        _write_sources_json(nodes)

        with open(graph_path, 'w') as f:
            json.dump(graph_data, f, indent=2)
        render_path = BASE_DIR / 'graph_3d_render.json'
        _atomic_write_json(render_path, render_graph)

        print(f"Updated graph with {len(nodes)} nodes and {len(edges)} edges")
        time.sleep(poll_interval)

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == '--streaming':
        # Use streaming mode for live updates
        build_graph_streaming(batch_size=3, delay_between_batches=1)
    elif len(sys.argv) > 1 and sys.argv[1] == '--live':
        # Use live polling mode - periodically fetch fresh data from all sources
        import time
        os.environ['ACE_T_LIVE_MODE'] = '1'
        poll_interval = int(os.environ.get('ACE_T_LIVE_POLL_INTERVAL', '300'))  # Default 5 minutes
        print(f"Starting live polling mode with {poll_interval}s intervals...")
        while True:
            try:
                build_graph()
                print(f"Live poll completed. Next poll in {poll_interval} seconds...")
            except KeyboardInterrupt:
                print("Live polling stopped by user.")
                break
            except Exception as e:
                print(f"Error during live poll: {e}")
            time.sleep(poll_interval)
    else:
        # Use regular mode for one-time builds
        build_graph()
