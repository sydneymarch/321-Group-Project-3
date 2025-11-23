"""
Utility functions for text processing and helper functions.
"""

import string
import re


def clean_text(text):
    """
    Clean and normalize text for keyword matching.
    
    Steps:
    1. Lowercase
    2. Strip punctuation
    3. Normalize whitespace
    
    Args:
        text (str): Raw text to clean
        
    Returns:
        str: Cleaned text
    """
    if not text:
        return ""
    
    # Lowercase
    text = text.lower()
    
    # Strip punctuation - replace with spaces to preserve word boundaries
    text = text.translate(str.maketrans(string.punctuation, ' ' * len(string.punctuation)))
    
    # Normalize whitespace - collapse multiple spaces into one
    text = re.sub(r'\s+', ' ', text)
    
    # Strip leading/trailing whitespace
    text = text.strip()
    
    return text


def stem_match(text, keyword):
    """
    Check if keyword (stem) exists in text using substring matching.
    
    This implements simple stemmed matching where a keyword like "infect"
    will match "infected", "infection", etc.
    
    Args:
        text (str): Cleaned text to search in
        keyword (str): Keyword/stem to search for
        
    Returns:
        bool: True if keyword found in text
    """
    if not text or not keyword:
        return False
    
    # Simple substring match - keyword should already be lowercased
    return keyword.lower() in text.lower()


def count_keyword_matches(text, keywords):
    """
    Count how many keywords from a list match in the text.
    
    Args:
        text (str): Cleaned text to search in
        keywords (list): List of keywords/stems to search for
        
    Returns:
        int: Number of unique keywords that matched
    """
    matches = 0
    for keyword in keywords:
        if stem_match(text, keyword):
            matches += 1
    return matches

