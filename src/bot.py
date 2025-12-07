"""
Threat Intelligence Bot - Main Orchestrator

Loads mock threat data, applies triage logic, and manages the Slack approval workflow.
"""

import json
import os
import time
from datetime import datetime
from dotenv import load_dotenv

from triage_engine import triage_all_threats, triage_threat
from slack_client import SlackThreatClient


# Load environment variables
load_dotenv()


class ThreatBot:
    """Main bot orchestrator for threat intelligence workflow."""
    
    def __init__(self):
        """Initialize the bot with Slack client and state management."""
        self.slack_client = SlackThreatClient()
        self.state_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'bot_state.json')
        self.state = self.load_state()
    
    def load_state(self):
        """
        Load bot state from JSON file.
        
        State tracks:
        - posted_threats: dict of threat_id -> {moderator_ts, moderator_channel, status}
        - approved_threats: list of threat_ids that have been posted to community
        
        Returns:
            dict: Bot state
        """
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Error loading state file: {e}")
                return self.initialize_state()
        else:
            return self.initialize_state()
    
    def initialize_state(self):
        """Initialize empty state structure."""
        return {
            'posted_threats': {},
            'approved_threats': [],
            'last_run': None
        }
    
    def save_state(self):
        """Save bot state to JSON file using atomic write."""
        try:
            # Write to temp file first, then atomic replace
            tmp_file = self.state_file + ".tmp"
            with open(tmp_file, 'w') as f:
                json.dump(self.state, f, indent=2)
            os.replace(tmp_file, self.state_file)
        except Exception as e:
            print(f"Error saving state file: {e}")
    
    def load_threats(self):
        """
        Load mock threat dataset.
        
        Returns:
            list: List of threat objects
        """
        threats_file = os.path.join(os.path.dirname(__file__), '..', 'data', 'mock_threat_dataset.json')
        try:
            with open(threats_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"Error loading threats: {e}")
            return []
    
    def post_new_threats(self):
        """
        Post new HIGH/MEDIUM priority threats to moderator channel.
        
        Returns:
            int: Number of threats posted
        """
        print("\n=== Loading and Triaging Threats ===")
        threats = self.load_threats()
        
        if not threats:
            print("No threats loaded.")
            return 0
        
        print(f"Loaded {len(threats)} threats from dataset")
        
        # Triage all threats
        triaged_threats = triage_all_threats(threats)
        
        # Filter for HIGH and MEDIUM priority only
        high_medium_threats = [
            (threat, result) for threat, result in triaged_threats
            if result['priority'] in ['HIGH', 'MEDIUM']
        ]
        
        print(f"Found {len(high_medium_threats)} HIGH/MEDIUM priority threats")
        
        # Post new threats (not already posted)
        posted_count = 0
        for threat, triage_result in high_medium_threats:
            threat_id = threat['id']
            
            # Skip if already posted
            if threat_id in self.state['posted_threats']:
                print(f"  {threat_id}: Already posted, skipping")
                continue
            
            # Post to moderator channel
            print(f"  {threat_id}: Posting to moderator channel ({triage_result['priority']} priority)")
            response = self.slack_client.post_to_moderator_channel(threat, triage_result)
            
            if response.get('ok'):
                # Track in state
                self.state['posted_threats'][threat_id] = {
                    'moderator_ts': response['ts'],
                    'moderator_channel': response['channel'],
                    'status': 'pending_approval',
                    'posted_at': datetime.now().isoformat(),
                    'priority': triage_result['priority']
                }
                posted_count += 1
                print(f"    ✓ Posted successfully (ts: {response['ts']})")
            else:
                print(f"    ✗ Failed to post: {response.get('error', 'Unknown error')}")
        
        if posted_count > 0:
            self.save_state()
            print(f"\nPosted {posted_count} new threats to moderator channel")
        else:
            print("\nNo new threats to post")
        
        return posted_count
    
    def check_approvals(self):
        """
        Check for approvals/rejections on pending threats.
        
        Handles three cases:
        1. ✅ reaction: Post original alert to community
        2. ❌ reaction + thread reply: Post the edited text to community
        3. ❌ reaction only: Reject without posting
        
        Returns:
            int: Number of threats approved/edited and posted
        """
        print("\n=== Checking for Approvals ===")
        
        # Get pending threats
        pending_threats = {
            threat_id: info for threat_id, info in self.state['posted_threats'].items()
            if info.get('status') == 'pending_approval'
        }
        
        if not pending_threats:
            print("No pending approvals")
            return 0
        
        print(f"Checking {len(pending_threats)} pending threats")
        
        # Load full threat data
        threats = self.load_threats()
        threats_dict = {t['id']: t for t in threats}
        
        approved_count = 0
        for threat_id, info in pending_threats.items():
            # Check for approval reaction (✅)
            is_approved = self.slack_client.check_approval(
                info['moderator_channel'],
                info['moderator_ts']
            )
            
            # Check for rejection reaction (❌)
            is_rejected = self.slack_client.check_rejection(
                info['moderator_channel'],
                info['moderator_ts']
            )
            
            # Get full threat data
            threat = threats_dict.get(threat_id)
            if not threat:
                print(f"  {threat_id}: ✗ Threat data not found, skipping")
                continue
            
            triage_result = triage_threat(threat)
            
            if is_approved:
                # Case 1: Approved as-is
                print(f"  {threat_id}: Approved! Posting original to community channel")
                
                response = self.slack_client.post_to_community_channel(threat, triage_result)
                
                if response.get('ok'):
                    self.state['posted_threats'][threat_id]['status'] = 'approved_posted'
                    self.state['posted_threats'][threat_id]['community_ts'] = response['ts']
                    self.state['posted_threats'][threat_id]['approved_at'] = datetime.now().isoformat()
                    self.state['approved_threats'].append(threat_id)
                    
                    self.slack_client.post_thread_reply(
                        info['moderator_channel'],
                        info['moderator_ts'],
                        f"✓ Posted to community channel at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                    )
                    
                    approved_count += 1
                    print(f"    ✓ Posted to community channel (ts: {response['ts']})")
                else:
                    print(f"    ✗ Failed to post: {response.get('error', 'Unknown error')}")
                    
            elif is_rejected:
                # Check for thread replies (edited text)
                replies = self.slack_client.get_thread_replies(
                    info['moderator_channel'],
                    info['moderator_ts']
                )
                
                if replies:
                    # Case 2: Rejected with edit - use the most recent reply
                    custom_text = replies[-1].get('text', '')
                    print(f"  {threat_id}: Rejected with edit! Posting custom text to community channel")
                    
                    response = self.slack_client.post_custom_community_alert(
                        threat, triage_result, custom_text
                    )
                    
                    if response.get('ok'):
                        self.state['posted_threats'][threat_id]['status'] = 'edited_posted'
                        self.state['posted_threats'][threat_id]['community_ts'] = response['ts']
                        self.state['posted_threats'][threat_id]['approved_at'] = datetime.now().isoformat()
                        self.state['posted_threats'][threat_id]['edited'] = True
                        self.state['approved_threats'].append(threat_id)
                        
                        self.slack_client.post_thread_reply(
                            info['moderator_channel'],
                            info['moderator_ts'],
                            f"✓ Posted EDITED alert to community channel at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        )
                        
                        approved_count += 1
                        print(f"    ✓ Posted edited alert to community channel (ts: {response['ts']})")
                    else:
                        print(f"    ✗ Failed to post: {response.get('error', 'Unknown error')}")
                else:
                    # Case 3: Rejected without edit - mark as rejected, don't post
                    print(f"  {threat_id}: Rejected (no edit provided)")
                    self.state['posted_threats'][threat_id]['status'] = 'rejected'
                    self.state['posted_threats'][threat_id]['rejected_at'] = datetime.now().isoformat()
                    
                    self.slack_client.post_thread_reply(
                        info['moderator_channel'],
                        info['moderator_ts'],
                        f"✗ Rejected at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - not posted to community"
                    )
                    print(f"    ✗ Marked as rejected")
            else:
                print(f"  {threat_id}: Still pending approval")
        
        if approved_count > 0:
            self.save_state()
            print(f"\nApproved/edited and posted {approved_count} threats to community channel")
        else:
            # Still save state if any rejections occurred
            self.save_state()
            print("\nNo new approvals")
        
        return approved_count
    
    def run(self):
        """
        Main bot execution workflow.
        
        Steps:
        1. Post new HIGH/MEDIUM threats to moderator channel
        2. Check pending threats for approvals
        3. Post approved threats to community channel
        """
        print("=" * 60)
        print("THREAT INTELLIGENCE BOT - RUN STARTED")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        try:
            # Step 1: Post new threats
            posted_count = self.post_new_threats()
            
            # Step 2: Check for approvals
            approved_count = self.check_approvals()
            
            # Update last run time
            self.state['last_run'] = datetime.now().isoformat()
            self.save_state()
            
            # Summary
            print("\n" + "=" * 60)
            print("RUN SUMMARY")
            print(f"  New threats posted: {posted_count}")
            print(f"  Threats approved: {approved_count}")
            print(f"  Total pending: {sum(1 for info in self.state['posted_threats'].values() if info.get('status') == 'pending_approval')}")
            print(f"  Total approved: {len(self.state['approved_threats'])}")
            print("=" * 60)
            
        except Exception as e:
            print(f"\n!!! ERROR during bot run: {e}")
            import traceback
            traceback.print_exc()
    
    def status(self):
        """Print current bot status."""
        print("\n" + "=" * 60)
        print("BOT STATUS")
        print("=" * 60)
        print(f"Last run: {self.state.get('last_run', 'Never')}")
        print(f"Total threats posted: {len(self.state['posted_threats'])}")
        print(f"Total approved: {len(self.state['approved_threats'])}")
        
        pending = [tid for tid, info in self.state['posted_threats'].items() if info.get('status') == 'pending_approval']
        print(f"Currently pending approval: {len(pending)}")
        
        if pending:
            print("\nPending threats:")
            for tid in pending:
                info = self.state['posted_threats'][tid]
                print(f"  - {tid} ({info.get('priority', 'UNKNOWN')}) posted at {info.get('posted_at', 'unknown')}")
        
        print("=" * 60)


def main():
    """Main entry point - runs continuously."""
    bot = ThreatBot()
    
    CHECK_INTERVAL = int(os.getenv('CHECK_INTERVAL', 30))  # 30 sec default
    
    print("=" * 60)
    print("THREAT BOT - CONTINUOUS MODE")
    print(f"Checking every {CHECK_INTERVAL} seconds")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    while True:
        try:
            bot.run()
        except KeyboardInterrupt:
            print("\nBot stopped by user.")
            break
        except Exception as e:
            print(f"Error during run: {e}")
            import traceback
            traceback.print_exc()
        
        print(f"\nNext check in {CHECK_INTERVAL} seconds...\n")
        time.sleep(CHECK_INTERVAL)


if __name__ == '__main__':
    main()

