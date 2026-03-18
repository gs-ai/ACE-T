#!/usr/bin/env python3
"""
THREAT_POSITIONER - Local Intelligence Engine
Processes raw threat records, normalizes, deduplicates, enriches, scores, and positions threats in 3D space.
Output: Strictly structured JSON only.
"""

import json
import sys
import hashlib
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import math
import random

class ThreatPositioner:
    def __init__(self):
        self.normalization_rules = {
            'ip': self._normalize_ip,
            'domain': self._normalize_domain,
            'url': self._normalize_url,
            'email': self._normalize_email,
            'hash': self._normalize_hash,
            'port': self._normalize_port,
            'protocol': self._normalize_protocol,
            'timestamp': self._normalize_timestamp
        }

    def process_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main processing pipeline"""
        timestamp_utc = input_data.get('timestamp_utc', datetime.utcnow().isoformat() + 'Z')
        source = input_data.get('source', 'unknown')
        records = input_data.get('records', [])
        prior_state = input_data.get('prior_state', {'threats': [], 'index': {'fingerprint_to_threat_id': {}}})

        # Normalize and deduplicate records
        normalized_records = self._normalize_records(records)

        # Process against prior state
        updated_threats, updated_index = self._process_against_prior_state(
            normalized_records, prior_state, timestamp_utc, source
        )

        # Position threats in 3D space
        positioned_threats = self._position_threats(updated_threats)

        return {
            'timestamp_utc': timestamp_utc,
            'processed_records': len(records),
            'normalized_records': len(normalized_records),
            'total_threats': len(positioned_threats),
            'threats': positioned_threats,
            'index': updated_index,
            'lifecycle_summary': self._get_lifecycle_summary(positioned_threats)
        }

    def _normalize_records(self, records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Normalize raw threat records"""
        normalized = []

        for record in records:
            normalized_record = {}

            # Apply normalization rules to each field
            for key, value in record.items():
                if key in self.normalization_rules and value is not None:
                    normalized_record[key] = self.normalization_rules[key](value)
                else:
                    normalized_record[key] = value

            # Generate fingerprint for deduplication
            fingerprint = self._generate_fingerprint(normalized_record)
            normalized_record['fingerprint'] = fingerprint

            # Calculate confidence score
            normalized_record['confidence_score'] = self._calculate_confidence(record)

            # Determine threat category
            normalized_record['category'] = self._categorize_threat(record)

            # Set initial lifecycle stage
            normalized_record['lifecycle_stage'] = 'new'

            normalized.append(normalized_record)

        return normalized

    def _normalize_ip(self, ip: str) -> str:
        """Normalize IP address"""
        ip = ip.strip()
        # Basic validation - could be enhanced
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
            return ip
        return ip.lower()

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain name"""
        return domain.strip().lower()

    def _normalize_url(self, url: str) -> str:
        """Normalize URL"""
        url = url.strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return url.lower()

    def _normalize_email(self, email: str) -> str:
        """Normalize email address"""
        return email.strip().lower()

    def _normalize_hash(self, hash_val: str) -> str:
        """Normalize hash"""
        return hash_val.strip().lower()

    def _normalize_port(self, port: Any) -> int:
        """Normalize port number"""
        try:
            return int(port)
        except (ValueError, TypeError):
            return 0

    def _normalize_protocol(self, protocol: str) -> str:
        """Normalize protocol name"""
        protocol = protocol.strip().upper()
        # Standardize common protocols
        protocol_map = {
            'TCP': 'TCP',
            'UDP': 'UDP',
            'HTTP': 'HTTP',
            'HTTPS': 'HTTPS',
            'SSH': 'SSH',
            'FTP': 'FTP',
            'SMTP': 'SMTP',
            'DNS': 'DNS',
            'ICMP': 'ICMP'
        }
        return protocol_map.get(protocol, protocol)

    def _normalize_timestamp(self, timestamp: Any) -> str:
        """Normalize timestamp to UTC ISO-8601"""
        if isinstance(timestamp, str):
            # Try to parse various formats
            try:
                # Assume it's already ISO format
                datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return timestamp
            except:
                # Fallback to current time
                pass
        return datetime.now().isoformat() + 'Z'

    def _generate_fingerprint(self, record: Dict[str, Any]) -> str:
        """Generate unique fingerprint for deduplication"""
        # Use key identifying fields to create fingerprint
        key_fields = ['ioc', 'ip', 'domain', 'url', 'email', 'hash', 'malware_family', 'actor']
        fingerprint_parts = []

        for field in key_fields:
            value = record.get(field)
            if value:
                fingerprint_parts.append(f"{field}:{value}")

        if not fingerprint_parts:
            # Fallback to entire record
            fingerprint_parts = [str(record)]

        fingerprint_str = '|'.join(sorted(fingerprint_parts))
        return hashlib.md5(fingerprint_str.encode()).hexdigest()

    def _calculate_confidence(self, record: Dict[str, Any]) -> float:
        """Calculate confidence score 0.0-1.0"""
        confidence = 0.5  # Base confidence

        # Boost based on available indicators
        indicators = ['ioc', 'ip', 'domain', 'url', 'email', 'hash', 'malware', 'actor']
        indicator_count = sum(1 for ind in indicators if record.get(ind))

        confidence += min(indicator_count * 0.1, 0.3)

        # Boost based on explicit confidence fields
        if 'predicted_prob' in record:
            confidence = max(confidence, float(record['predicted_prob']))
        if 'confidence' in record:
            confidence = max(confidence, float(record['confidence']) / 100.0 if float(record['confidence']) > 1 else float(record['confidence']))

        return min(confidence, 1.0)

    def _categorize_threat(self, record: Dict[str, Any]) -> str:
        """Categorize threat type"""
        # Check for explicit categories
        if 'category' in record:
            return record['category']
        if 'predicted_label' in record:
            return record['predicted_label']
        if 'attack_type' in record:
            return record['attack_type']

        # Infer from indicators
        if record.get('malware') or record.get('malware_family'):
            return 'malware'
        if record.get('actor') or record.get('group'):
            return 'apt'
        if record.get('ip') or record.get('domain'):
            return 'network'
        if record.get('url'):
            return 'web'
        if record.get('email'):
            return 'phishing'

        return 'unknown'

    def _process_against_prior_state(self, normalized_records: List[Dict[str, Any]],
                                   prior_state: Dict[str, Any], timestamp_utc: str,
                                   source: str) -> tuple:
        """Process new records against prior state for deduplication and updates"""
        prior_threats = {t['id']: t for t in prior_state.get('threats', [])}
        fingerprint_index = prior_state.get('index', {}).get('fingerprint_to_threat_id', {})

        updated_threats = []
        updated_index = dict(fingerprint_index)

        for record in normalized_records:
            fingerprint = record['fingerprint']

            if fingerprint in updated_index:
                # Update existing threat
                threat_id = updated_index[fingerprint]
                existing_threat = prior_threats.get(threat_id, {})

                # Merge and update
                updated_threat = self._merge_threat_records(existing_threat, record, timestamp_utc, source)
                updated_threats.append(updated_threat)
            else:
                # New threat
                new_threat = self._create_new_threat(record, timestamp_utc, source)
                threat_id = new_threat['id']
                updated_index[fingerprint] = threat_id
                updated_threats.append(new_threat)

        # Include prior threats that weren't updated (aging)
        for threat_id, threat in prior_threats.items():
            if threat_id not in [t['id'] for t in updated_threats]:
                aged_threat = self._age_threat(threat, timestamp_utc)
                if aged_threat:  # Only include if not resolved
                    updated_threats.append(aged_threat)

        return updated_threats, {'fingerprint_to_threat_id': updated_index}

    def _create_new_threat(self, record: Dict[str, Any], timestamp: str, source: str) -> Dict[str, Any]:
        """Create new threat entry"""
        threat_id = f"threat_{int(datetime.now().timestamp() * 1000000)}"

        return {
            'id': threat_id,
            'fingerprint': record['fingerprint'],
            'category': record['category'],
            'confidence_score': record['confidence_score'],
            'lifecycle_stage': 'new',
            'first_seen': timestamp,
            'last_seen': timestamp,
            'last_updated': timestamp,
            'source': source,
            'record_count': 1,
            'indicators': self._extract_indicators(record),
            'metadata': self._extract_metadata(record),
            'history': [{
                'timestamp': timestamp,
                'stage': 'new',
                'confidence': record['confidence_score'],
                'source': source
            }]
        }

    def _merge_threat_records(self, existing: Dict[str, Any], new_record: Dict[str, Any],
                            timestamp: str, source: str) -> Dict[str, Any]:
        """Merge new record with existing threat"""
        # Ensure existing threat has required fields
        threat_id = existing.get('id', new_record.get('id', f"threat_{int(datetime.now().timestamp() * 1000000)}"))
        fingerprint = existing.get('fingerprint', new_record.get('fingerprint', self._generate_fingerprint(new_record)))
        
        # Update lifecycle stage
        new_stage = self._determine_lifecycle_stage(existing, new_record, timestamp)

        # Update confidence (weighted average)
        total_records = existing.get('record_count', 1) + 1
        existing_conf = existing.get('confidence_score', 0.5)
        new_conf = new_record['confidence_score']
        updated_conf = (existing_conf * (total_records - 1) + new_conf) / total_records

        # Update metadata
        updated_metadata = dict(existing.get('metadata', {}))
        updated_metadata.update(self._extract_metadata(new_record))

        # Add to history
        history = existing.get('history', [])
        history.append({
            'timestamp': timestamp,
            'stage': new_stage,
            'confidence': new_conf,
            'source': source
        })

        # Keep only last 10 history entries
        history = history[-10:]

        return {
            'id': threat_id,
            'fingerprint': fingerprint,
            'category': existing.get('category', new_record.get('category', 'unknown')),  # Keep original category
            'confidence_score': updated_conf,
            'lifecycle_stage': new_stage,
            'first_seen': existing.get('first_seen', timestamp),
            'last_seen': timestamp,
            'last_updated': timestamp,
            'source': source,
            'record_count': total_records,
            'indicators': self._merge_indicators(existing.get('indicators', {}), new_record),
            'metadata': updated_metadata,
            'history': history
        }

    def _age_threat(self, threat: Dict[str, Any], current_timestamp: str) -> Optional[Dict[str, Any]]:
        """Age existing threat if not recently updated"""
        last_updated = threat.get('last_updated', threat.get('first_seen', current_timestamp))
        last_dt = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
        current_dt = datetime.fromisoformat(current_timestamp.replace('Z', '+00:00'))

        days_since_update = (current_dt - last_dt).days

        if days_since_update > 30:
            # Mark as dormant or resolved
            if threat.get('lifecycle_stage') in ['active', 'degrading']:
                threat['lifecycle_stage'] = 'dormant'
            elif threat.get('lifecycle_stage') == 'dormant':
                threat['lifecycle_stage'] = 'resolved'
                return None  # Remove resolved threats
        elif days_since_update > 7 and threat.get('lifecycle_stage') == 'active':
            threat['lifecycle_stage'] = 'degrading'

        threat['last_updated'] = current_timestamp
        return threat

    def _determine_lifecycle_stage(self, existing: Dict[str, Any], new_record: Dict[str, Any], timestamp: str) -> str:
        """Determine lifecycle stage transition"""
        current_stage = existing.get('lifecycle_stage', 'new')
        new_confidence = new_record['confidence_score']

        # Simple state machine
        if current_stage == 'new':
            return 'active'
        elif current_stage in ['active', 'degrading']:
            if new_confidence > 0.8:
                return 'active'
            else:
                return 'degrading'
        elif current_stage == 'dormant':
            return 'active'  # Reactivated

        return current_stage

    def _extract_indicators(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Extract threat indicators"""
        indicators = {}
        indicator_fields = ['ioc', 'ip', 'domain', 'url', 'email', 'hash', 'port', 'protocol',
                          'malware', 'malware_family', 'actor', 'group', 'ja3', 'sni']

        for field in indicator_fields:
            if field in record and record[field]:
                indicators[field] = record[field]

        return indicators

    def _extract_metadata(self, record: Dict[str, Any]) -> Dict[str, Any]:
        """Extract metadata"""
        metadata = {}
        meta_fields = ['description', 'notes', 'predicted_label', 'attack_type', 'vendor_confidence',
                      'last_modified', 'age_days', 'downloads', 'likes', 'report_count', 'reporting_source']

        for field in meta_fields:
            if field in record and record[field] is not None:
                metadata[field] = record[field]

        return metadata

    def _merge_indicators(self, existing: Dict[str, Any], new_record: Dict[str, Any]) -> Dict[str, Any]:
        """Merge indicators from multiple records"""
        merged = dict(existing)

        new_indicators = self._extract_indicators(new_record)
        for key, value in new_indicators.items():
            if key not in merged:
                merged[key] = value
            elif isinstance(merged[key], list):
                if value not in merged[key]:
                    merged[key].append(value)
            else:
                if merged[key] != value:
                    merged[key] = [merged[key], value]

        return merged

    def _position_threats(self, threats: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Position threats in 3D space based on category, confidence, and lifecycle"""
        positioned = []

        for threat in threats:
            position = self._calculate_3d_position(threat)
            threat_with_position = dict(threat)
            threat_with_position.update(position)
            positioned.append(threat_with_position)

        return positioned

    def _calculate_3d_position(self, threat: Dict[str, Any]) -> Dict[str, float]:
        """Calculate 3D position for threat"""
        category = threat.get('category', 'unknown')
        confidence = threat.get('confidence_score', 0.5)
        stage = threat.get('lifecycle_stage', 'new')
        record_count = threat.get('record_count', 1)

        # Base position by category
        category_positions = {
            'malware': {'x': 10, 'y': 0, 'z': 0},
            'apt': {'x': -10, 'y': 0, 'z': 0},
            'network': {'x': 0, 'y': 10, 'z': 0},
            'web': {'x': 0, 'y': -10, 'z': 0},
            'phishing': {'x': 0, 'y': 0, 'z': 10},
            'unknown': {'x': 0, 'y': 0, 'z': -10}
        }

        base_pos = category_positions.get(category, {'x': 0, 'y': 0, 'z': 0})

        # Adjust by confidence (higher confidence = closer to center/more prominent)
        confidence_factor = 1.0 - confidence  # 0 = high confidence (center), 1 = low (periphery)
        radius = confidence_factor * 15

        # Adjust by lifecycle stage
        stage_multipliers = {
            'new': 1.2,
            'active': 1.0,
            'degrading': 0.8,
            'dormant': 0.6,
            'resolved': 0.4
        }
        stage_multiplier = stage_multipliers.get(stage, 1.0)

        # Add some randomness based on threat ID for distribution
        threat_id = threat.get('id', 'unknown')
        random.seed(threat_id)
        angle1 = random.uniform(0, 2 * math.pi)
        angle2 = random.uniform(0, math.pi)

        # Calculate final position
        x = base_pos['x'] + radius * math.sin(angle1) * math.cos(angle2) * stage_multiplier
        y = base_pos['y'] + radius * math.sin(angle1) * math.sin(angle2) * stage_multiplier
        z = base_pos['z'] + radius * math.cos(angle1) * stage_multiplier

        # Add record count influence (more records = more central)
        record_influence = min(record_count / 10.0, 1.0)
        x *= (1.0 - record_influence * 0.3)
        y *= (1.0 - record_influence * 0.3)
        z *= (1.0 - record_influence * 0.3)

        return {
            'x': round(x, 3),
            'y': round(y, 3),
            'z': round(z, 3)
        }

    def _get_lifecycle_summary(self, threats: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get summary of threats by lifecycle stage"""
        summary = {}
        for threat in threats:
            stage = threat.get('lifecycle_stage', 'unknown')
            summary[stage] = summary.get(stage, 0) + 1
        return summary


def main():
    """Main entry point"""
    # Read input from stdin
    input_data = json.load(sys.stdin)

    # Process
    positioner = ThreatPositioner()
    result = positioner.process_input(input_data)

    # Output structured JSON only
    print(json.dumps(result, indent=2))

if __name__ == '__main__':
    main()
