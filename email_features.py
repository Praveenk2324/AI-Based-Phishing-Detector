import re
import numpy as np

# Spambase dataset attributes (57 features)
# 48 word_freq_WORD
MH_WORDS = [
    "make", "address", "all", "3d", "our", "over", "remove", "internet",
    "order", "mail", "receive", "will", "people", "report", "addresses",
    "free", "business", "email", "you", "credit", "your", "font", "000",
    "money", "hp", "hpl", "george", "650", "lab", "labs", "telnet", "857",
    "data", "415", "85", "technology", "1999", "parts", "pm", "direct",
    "cs", "meeting", "original", "project", "re", "edu", "table", "conference"
]

# 6 char_freq_CHAR
MH_CHARS = [";", "(", "[", "!", "$", "#"]

def extract_spambase_features(text):
    """
    Extracts the 57 features required for the Spambase model from raw email text.
    
    Args:
        text (str): The raw email text.
        
    Returns:
        numpy.ndarray: A 1x57 arrays of features.
    """
    if not text:
        return np.zeros((1, 57))
        
    features = []
    
    # Pre-processing: tokenize for word counting
    # We'll use a simple regex for tokenization similar to what might have been used
    # Note: Spambase documentation says "continuous real [0,100] attributes of type word_freq_WORD"
    # = percentage of words in the e-mail that match WORD
    
    # Split by non-alphanumeric characters to get words
    # This is a rough approximation.
    words = re.split(r'[^a-zA-Z0-9]', text)
    words = [w.lower() for w in words if w] # Filter empty strings and lowercase
    
    total_words = len(words)
    total_chars = len(text)
    
    if total_words == 0:
         # If no words, word freqs are 0
        features.extend([0.0] * 48)
    else:
        # 1-48: Word frequencies
        for target_word in MH_WORDS:
            count = words.count(target_word)
            freq = 100.0 * count / total_words
            features.append(freq)
            
    # 49-54: Character frequencies
    # percentage of characters in the e-mail that match CHAR
    if total_chars == 0:
        features.extend([0.0] * 6)
    else:
        for target_char in MH_CHARS:
            count = text.count(target_char)
            freq = 100.0 * count / total_chars
            features.append(freq)
            
    # Capital run length statistics
    # 55: capital_run_length_average
    # 56: capital_run_length_longest
    # 57: capital_run_length_total
    
    # Find all sequences of capital letters
    cap_runs = re.findall(r'[A-Z]+', text)
    
    if not cap_runs:
        features.extend([0.0, 0.0, 0.0])
    else:
        run_lengths = [len(run) for run in cap_runs]
        
        run_avg = sum(run_lengths) / len(run_lengths)
        run_max = max(run_lengths)
        run_total = sum(run_lengths)
        
        features.append(run_avg)
        features.append(run_max)
        features.append(run_total)
        
    return np.array([features])
