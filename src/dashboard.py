"""
Threat Intelligence Dashboard - Web Interface

Flask web application to display threat data, statistics, and reports.
"""

import json
import os
import sys
from datetime import datetime
from flask import Flask, render_template, jsonify

# Add parent directory to path to import bot modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from triage_engine import triage_all_threats, triage_threat

app = Flask(__name__)

# Get project root directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, 'data')


def load_threats():
    """Load threat data from JSON file."""
    threats_file = os.path.join(DATA_DIR, 'mock_threat_dataset.json')
    try:
        with open(threats_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading threats: {e}")
        return []


def load_bot_state():
    """Load bot state to see approval status."""
    state_file = os.path.join(DATA_DIR, 'bot_state.json')
    if os.path.exists(state_file):
        try:
            with open(state_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading state: {e}")
    return {'posted_threats': {}, 'approved_threats': [], 'last_run': None}


@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('dashboard.html')


@app.route('/api/threats')
def api_threats():
    """API endpoint to get all threats with triage results."""
    threats = load_threats()
    triaged = triage_all_threats(threats)
    
    # Get bot state for approval status
    state = load_bot_state()
    
    threats_data = []
    for threat, triage_result in triaged:
        threat_id = threat['id']
        
        # Check approval status
        approval_status = 'not_posted'
        if threat_id in state.get('posted_threats', {}):
            threat_info = state['posted_threats'][threat_id]
            if threat_info.get('status') == 'pending_approval':
                approval_status = 'pending'
            elif threat_info.get('status') == 'approved_posted':
                approval_status = 'approved'
        
        threat_data = {
            'id': threat_id,
            'title': threat.get('title', 'Unknown'),
            'description': threat.get('description', ''),
            'cvss': threat.get('cvss', 0),
            'date': threat.get('date', ''),
            'source_trust': threat.get('source_trust', ''),
            'asset_category': threat.get('asset_category', ''),
            'priority': triage_result['priority'],
            'explanation': triage_result.get('explanation', ''),
            'bucket_counts': triage_result.get('bucket_counts', {}),
            'buckets_hit': triage_result.get('buckets_hit', 0),
            'total_keyword_count': triage_result.get('total_keyword_count', 0),
            'auto_triggers': triage_result.get('auto_triggers', []),
            'approval_status': approval_status
        }
        threats_data.append(threat_data)
    
    return jsonify(threats_data)


@app.route('/api/statistics')
def api_statistics():
    """API endpoint to get dashboard statistics."""
    threats = load_threats()
    triaged = triage_all_threats(threats)
    state = load_bot_state()
    
    # Count by priority
    priority_counts = {'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for _, result in triaged:
        priority = result['priority']
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
    
    # Approval statistics
    posted_count = len(state.get('posted_threats', {}))
    approved_count = len(state.get('approved_threats', []))
    pending_count = sum(1 for info in state.get('posted_threats', {}).values() 
                       if info.get('status') == 'pending_approval')
    
    # Average CVSS score
    cvss_scores = [t.get('cvss', 0) for t in threats if t.get('cvss', 0) > 0]
    avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0
    
    stats = {
        'total_threats': len(threats),
        'priority_counts': priority_counts,
        'posted_to_moderator': posted_count,
        'approved': approved_count,
        'pending_approval': pending_count,
        'average_cvss': round(avg_cvss, 2),
        'last_run': state.get('last_run')
    }
    
    return jsonify(stats)


@app.route('/api/threat/<threat_id>')
def api_threat_detail(threat_id):
    """API endpoint to get detailed information about a specific threat."""
    threats = load_threats()
    threat = next((t for t in threats if t['id'] == threat_id), None)
    
    if not threat:
        return jsonify({'error': 'Threat not found'}), 404
    
    triage_result = triage_threat(threat)
    state = load_bot_state()
    
    # Get approval status
    approval_info = None
    approval_status = 'not_posted'
    if threat_id in state.get('posted_threats', {}):
        approval_info = state['posted_threats'][threat_id]
        if approval_info.get('status') == 'pending_approval':
            approval_status = 'pending'
        elif approval_info.get('status') == 'approved_posted':
            approval_status = 'approved'
    
    threat_data = {
        'id': threat_id,
        'title': threat.get('title', 'Unknown'),
        'description': threat.get('description', ''),
        'cvss': threat.get('cvss', 0),
        'date': threat.get('date', ''),
        'source_trust': threat.get('source_trust', ''),
        'asset_category': threat.get('asset_category', ''),
        'priority': triage_result['priority'],
        'explanation': triage_result.get('explanation', ''),
        'bucket_counts': triage_result.get('bucket_counts', {}),
        'buckets_hit': triage_result.get('buckets_hit', 0),
        'total_keyword_count': triage_result.get('total_keyword_count', 0),
        'auto_triggers': triage_result.get('auto_triggers', []),
        'approval_status': approval_status,
        'approval_info': approval_info
    }
    
    return jsonify(threat_data)


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE DASHBOARD")
    print("=" * 60)
    print("\nStarting web server...")
    print("Dashboard will be available at:")
    print("  http://localhost:5000")
    print("  http://127.0.0.1:5000")
    print("\nPress Ctrl+C to stop the server")
    print("=" * 60 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)

