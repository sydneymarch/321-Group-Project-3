"""
Triage engine for threat prioritization using rule-based scoring.

Implements the 4-bucket keyword matching system with automatic HIGH triggers.
"""

import json
import os
from utils import clean_text, stem_match


# Load critical assets configuration
def load_critical_assets():
    """Load the critical_assets.json configuration file."""
    config_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'critical_assets.json')
    with open(config_path, 'r') as f:
        return json.load(f)


# Global assets loaded once
CRITICAL_ASSETS = load_critical_assets()

# Bucket mappings
BUCKET_A_CATEGORIES = [cat for cat, data in CRITICAL_ASSETS.items() if data['impact'] == 'clinical']
BUCKET_B_CATEGORIES = [cat for cat, data in CRITICAL_ASSETS.items() if data['impact'] == 'biomanufacturing']
BUCKET_C_CATEGORIES = [cat for cat, data in CRITICAL_ASSETS.items() if data['impact'] == 'agriculture']
BUCKET_D_CATEGORIES = [cat for cat, data in CRITICAL_ASSETS.items() if data['impact'] == 'severity']

# Automatic HIGH triggers
AUTO_HIGH_KEYWORDS = [
    'unpatch',
    'no patch',
    'infect',
    'sole-source',
    'sole source',
    'multi-state',
    'multi state',
    'multi-country',
    'multi country',
    'outbreak',
    'wastewater'
]


def check_auto_high_triggers(cleaned_text, cvss_score):
    """
    Check for automatic HIGH priority triggers.
    
    Triggers:
    - "unpatch", "no patch"
    - CVSS >= 9
    - "infect"
    - "sole-source", "sole source"
    - "multi-state", "multi-country", "outbreak", "wastewater"
    
    Args:
        cleaned_text (str): Cleaned threat description
        cvss_score (int/float): CVSS score
        
    Returns:
        tuple: (bool: triggered, list: trigger reasons)
    """
    triggers = []
    
    # Check CVSS
    if cvss_score >= 9:
        triggers.append(f"CVSS >= 9 (score: {cvss_score})")
    
    # Check keywords
    for keyword in AUTO_HIGH_KEYWORDS:
        if stem_match(cleaned_text, keyword):
            triggers.append(f"Keyword: '{keyword}'")
    
    return len(triggers) > 0, triggers


def count_bucket_matches(cleaned_text, bucket_categories):
    """
    Count keyword matches for a specific bucket.
    
    Args:
        cleaned_text (str): Cleaned threat description
        bucket_categories (list): List of category names in this bucket
        
    Returns:
        int: Total keyword matches in this bucket
    """
    count = 0
    for category in bucket_categories:
        keywords = CRITICAL_ASSETS[category]['keywords']
        for keyword in keywords:
            if stem_match(cleaned_text, keyword):
                count += 1
    return count


def triage_threat(threat_obj):
    """
    Apply rule-based triage to a threat object.
    
    Priority Rules:
    - HIGH: Any automatic trigger OR buckets_hit >= 2 OR (buckets_hit == 1 AND bucket_count >= 7)
    - MEDIUM: buckets_hit == 1 AND bucket_count in [2..6] OR CVSS 6-8 (no auto triggers)
    - LOW: No bucket matches OR only 1 keyword OR text < 200 chars
    
    Args:
        threat_obj (dict): Threat object with 'description', 'cvss', etc.
        
    Returns:
        dict: {
            'priority': 'HIGH' | 'MEDIUM' | 'LOW',
            'explanation': str,
            'bucket_counts': dict,
            'auto_triggers': list
        }
    """
    # Extract fields
    description = threat_obj.get('description', '')
    title = threat_obj.get('title', '')
    cvss = threat_obj.get('cvss', 0)
    
    # Combine title and description for analysis
    full_text = f"{title} {description}"
    
    # Clean text
    cleaned_text = clean_text(full_text)
    
    # Check text length (LOW priority if < 200 chars)
    if len(full_text) < 200:
        return {
            'priority': 'LOW',
            'explanation': f'Text too short ({len(description)} chars < 200 chars threshold)',
            'bucket_counts': {'A': 0, 'B': 0, 'C': 0, 'D': 0},
            'auto_triggers': []
        }
    
    # Check automatic HIGH triggers
    auto_high, auto_triggers = check_auto_high_triggers(cleaned_text, cvss)
    
    # Count bucket matches
    A_count = count_bucket_matches(cleaned_text, BUCKET_A_CATEGORIES)
    B_count = count_bucket_matches(cleaned_text, BUCKET_B_CATEGORIES)
    C_count = count_bucket_matches(cleaned_text, BUCKET_C_CATEGORIES)
    D_count = count_bucket_matches(cleaned_text, BUCKET_D_CATEGORIES)
    
    # Calculate buckets hit (how many buckets have at least 1 match)
    buckets_hit = sum([
        1 if A_count > 0 else 0,
        1 if B_count > 0 else 0,
        1 if C_count > 0 else 0,
        1 if D_count > 0 else 0
    ])
    
    # Get the count of the single bucket hit (if only 1 bucket)
    if buckets_hit == 1:
        bucket_count = max(A_count, B_count, C_count, D_count)
    else:
        bucket_count = sum([A_count, B_count, C_count, D_count])
    
    bucket_counts = {'A': A_count, 'B': B_count, 'C': C_count, 'D': D_count}
    
    # Apply priority rules
    explanation_parts = []
    
    # HIGH PRIORITY conditions
    if auto_high:
        priority = 'HIGH'
        explanation_parts.append(f"Automatic HIGH triggers: {', '.join(auto_triggers)}")
    elif buckets_hit >= 2:
        priority = 'HIGH'
        explanation_parts.append(f"Multiple buckets hit ({buckets_hit} buckets)")
        explanation_parts.append(f"Bucket counts: A={A_count}, B={B_count}, C={C_count}, D={D_count}")
    elif buckets_hit == 1 and bucket_count >= 7:
        priority = 'HIGH'
        explanation_parts.append(f"Single bucket with high keyword count ({bucket_count} keywords)")
        explanation_parts.append(f"Bucket counts: A={A_count}, B={B_count}, C={C_count}, D={D_count}")
    # MEDIUM PRIORITY conditions
    elif buckets_hit == 1 and 2 <= bucket_count <= 6:
        priority = 'MEDIUM'
        explanation_parts.append(f"Single bucket with moderate keyword count ({bucket_count} keywords)")
        explanation_parts.append(f"Bucket counts: A={A_count}, B={B_count}, C={C_count}, D={D_count}")
    elif 6 <= cvss <= 8 and not auto_high:
        priority = 'MEDIUM'
        explanation_parts.append(f"CVSS score in medium range ({cvss})")
        explanation_parts.append(f"Bucket counts: A={A_count}, B={B_count}, C={C_count}, D={D_count}")
    # LOW PRIORITY (default)
    else:
        priority = 'LOW'
        if buckets_hit == 0:
            explanation_parts.append("No bucket keyword matches")
        elif bucket_count == 1:
            explanation_parts.append("Only 1 keyword match")
        else:
            explanation_parts.append(f"Does not meet HIGH or MEDIUM criteria (buckets_hit={buckets_hit}, bucket_count={bucket_count}, CVSS={cvss})")
        explanation_parts.append(f"Bucket counts: A={A_count}, B={B_count}, C={C_count}, D={D_count}")
    
    return {
        'priority': priority,
        'explanation': ' | '.join(explanation_parts),
        'bucket_counts': bucket_counts,
        'auto_triggers': auto_triggers,
        'buckets_hit': buckets_hit,
        'total_keyword_count': bucket_count
    }


def triage_all_threats(threats):
    """
    Triage a list of threats.
    
    Args:
        threats (list): List of threat objects
        
    Returns:
        list: List of tuples (threat_obj, triage_result)
    """
    results = []
    for threat in threats:
        triage_result = triage_threat(threat)
        results.append((threat, triage_result))
    return results

