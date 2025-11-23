"""
Slack API client wrapper for threat bot communications.

Handles posting messages, checking reactions, and managing the approval workflow.
"""

import os
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


class SlackThreatClient:
    """Wrapper around Slack WebClient for threat alert posting and approval checking."""
    
    def __init__(self, token=None):
        """
        Initialize Slack client.
        
        Args:
            token (str, optional): Slack bot token. If None, reads from SLACK_BOT_TOKEN env var.
        """
        self.token = token or os.getenv('SLACK_BOT_TOKEN')
        if not self.token:
            raise ValueError("SLACK_BOT_TOKEN not provided and not found in environment")
        
        self.client = WebClient(token=self.token)
        
        # Load channel IDs from environment
        self.moderator_channel = os.getenv('SLACK_MODERATOR_CHANNEL')
        self.community_channel = os.getenv('SLACK_COMMUNITY_CHANNEL')
        
        if not self.moderator_channel or not self.community_channel:
            raise ValueError("SLACK_MODERATOR_CHANNEL and SLACK_COMMUNITY_CHANNEL must be set")
    
    def create_threat_blocks(self, threat, triage_result, include_approval_note=False):
        """
        Create Slack Block Kit formatted blocks for a threat alert.
        
        Args:
            threat (dict): Threat object
            triage_result (dict): Triage analysis result
            include_approval_note (bool): Whether to include moderator approval instructions
            
        Returns:
            list: Slack blocks for the message
        """
        priority = triage_result['priority']
        
        # Priority emoji
        priority_emoji = {
            'HIGH': ':red_circle:',
            'MEDIUM': ':large_orange_diamond:',
            'LOW': ':white_circle:'
        }
        
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{priority_emoji.get(priority, '')} {priority} PRIORITY: {threat['id']}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{threat['title']}*"
                }
            },
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*CVSS Score:*\n{threat.get('cvss', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Source Trust:*\n{threat.get('source_trust', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Date:*\n{threat.get('date', 'N/A')}"
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Asset Category:*\n{threat.get('asset_category', 'N/A')}"
                    }
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Description:*\n{threat.get('description', 'No description')}"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Triage Analysis:*\n{triage_result.get('explanation', 'N/A')}"
                }
            },
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": f"Bucket Hits: {triage_result.get('buckets_hit', 0)} | "
                               f"Keyword Count: {triage_result.get('total_keyword_count', 0)} | "
                               f"A:{triage_result['bucket_counts']['A']} "
                               f"B:{triage_result['bucket_counts']['B']} "
                               f"C:{triage_result['bucket_counts']['C']} "
                               f"D:{triage_result['bucket_counts']['D']}"
                    }
                ]
            }
        ]
        
        if include_approval_note:
            blocks.append({
                "type": "divider"
            })
            blocks.append({
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": ":white_check_mark: *React with ✅ to approve posting to community channel*"
                }
            })
        
        return blocks
    
    def send_message(self, channel, blocks, text=None):
        """
        Send a message to a Slack channel.
        
        Args:
            channel (str): Channel ID
            blocks (list): Slack blocks
            text (str, optional): Fallback text
            
        Returns:
            dict: Response from Slack API containing 'ts' (timestamp) and 'channel'
        """
        try:
            response = self.client.chat_postMessage(
                channel=channel,
                blocks=blocks,
                text=text or "Threat Alert"
            )
            return {
                'ok': True,
                'ts': response['ts'],
                'channel': response['channel']
            }
        except SlackApiError as e:
            print(f"Error sending message: {e.response['error']}")
            return {
                'ok': False,
                'error': e.response['error']
            }
    
    def post_to_moderator_channel(self, threat, triage_result):
        """
        Post a threat alert to the moderator channel for approval.
        
        Args:
            threat (dict): Threat object
            triage_result (dict): Triage analysis result
            
        Returns:
            dict: Response containing message timestamp
        """
        blocks = self.create_threat_blocks(threat, triage_result, include_approval_note=True)
        return self.send_message(
            self.moderator_channel,
            blocks,
            text=f"{triage_result['priority']} PRIORITY: {threat['title']}"
        )
    
    def post_to_community_channel(self, threat, triage_result):
        """
        Post an approved threat alert to the community channel.
        
        Args:
            threat (dict): Threat object
            triage_result (dict): Triage analysis result
            
        Returns:
            dict: Response containing message timestamp
        """
        blocks = self.create_threat_blocks(threat, triage_result, include_approval_note=False)
        return self.send_message(
            self.community_channel,
            blocks,
            text=f"{triage_result['priority']} PRIORITY: {threat['title']}"
        )
    
    def get_reactions(self, channel, timestamp):
        """
        Get reactions on a specific message.
        
        Args:
            channel (str): Channel ID
            timestamp (str): Message timestamp
            
        Returns:
            list: List of reaction objects, or empty list on error
        """
        try:
            response = self.client.reactions_get(
                channel=channel,
                timestamp=timestamp
            )
            if response['ok'] and 'message' in response and 'reactions' in response['message']:
                return response['message']['reactions']
            return []
        except SlackApiError as e:
            print(f"Error getting reactions: {e.response['error']}")
            return []
    
    def check_approval(self, channel, timestamp, approval_emoji='white_check_mark'):
        """
        Check if a message has been approved (has the approval emoji reaction).
        
        Args:
            channel (str): Channel ID
            timestamp (str): Message timestamp
            approval_emoji (str): Emoji name to check for (without colons)
            
        Returns:
            bool: True if message has approval reaction
        """
        reactions = self.get_reactions(channel, timestamp)
        for reaction in reactions:
            if reaction.get('name') == approval_emoji and reaction.get('count', 0) > 0:
                return True
        return False
    
    def post_thread_reply(self, channel, thread_ts, text):
        """
        Post a reply in a thread.
        
        Args:
            channel (str): Channel ID
            thread_ts (str): Thread timestamp (parent message)
            text (str): Reply text
            
        Returns:
            dict: Response from Slack API
        """
        try:
            response = self.client.chat_postMessage(
                channel=channel,
                thread_ts=thread_ts,
                text=text
            )
            return {'ok': True, 'ts': response['ts']}
        except SlackApiError as e:
            print(f"Error posting thread reply: {e.response['error']}")
            return {'ok': False, 'error': e.response['error']}
    
    def send_ephemeral(self, channel, user, text):
        """
        Send an ephemeral message (only visible to specific user).
        
        Args:
            channel (str): Channel ID
            user (str): User ID
            text (str): Message text
            
        Returns:
            dict: Response from Slack API
        """
        try:
            response = self.client.chat_postEphemeral(
                channel=channel,
                user=user,
                text=text
            )
            return {'ok': True}
        except SlackApiError as e:
            print(f"Error sending ephemeral message: {e.response['error']}")
            return {'ok': False, 'error': e.response['error']}
    
    def send_dm(self, user_id, text):
        """
        Send a direct message to a user.
        
        Args:
            user_id (str): User ID
            text (str): Message text
            
        Returns:
            dict: Response from Slack API
        """
        try:
            # Open a DM channel with the user
            dm_response = self.client.conversations_open(users=user_id)
            if not dm_response['ok']:
                return {'ok': False, 'error': 'Failed to open DM channel'}
            
            channel_id = dm_response['channel']['id']
            
            # Send the message
            response = self.client.chat_postMessage(
                channel=channel_id,
                text=text
            )
            return {'ok': True, 'ts': response['ts']}
        except SlackApiError as e:
            print(f"Error sending DM: {e.response['error']}")
            return {'ok': False, 'error': e.response['error']}

