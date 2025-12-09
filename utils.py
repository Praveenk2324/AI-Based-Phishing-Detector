from urllib.parse import urlparse

# Moved extract_features_from_url to legacy_v1/legacy_utils.py
# Moved is_domain_active to legacy_v1/legacy_utils.py

def get_whitelisted_domains():
    """
    Returns a set of popular legitimate domains to strictly prevent false positives.
    """
    return {
        'google.com', 'www.google.com', 'youtube.com', 'www.youtube.com',
        'facebook.com', 'www.facebook.com', 'amazon.com', 'www.amazon.com',
        'wikipedia.org', 'www.wikipedia.org', 'instagram.com', 'www.instagram.com',
        'twitter.com', 'www.twitter.com', 'linkedin.com', 'www.linkedin.com',
        'reddit.com', 'www.reddit.com', 'netflix.com', 'www.netflix.com',
        'microsoft.com', 'www.microsoft.com', 'apple.com', 'www.apple.com',
        'yahoo.com', 'www.yahoo.com', 'bing.com', 'www.bing.com',
        'github.com', 'www.github.com', 'stackoverflow.com', 'gmail.com'
    }

def is_whitelisted(url):
    try:
        parsed = urlparse(url)
        hostname = parsed.netloc
        if not hostname:
             path = parsed.path
             if '/' in path:
                 hostname = path.split('/')[0]
             else:
                 hostname = path
        
        # Remove port
        if ':' in hostname:
            hostname = hostname.split(':')[0]
            
        return hostname.lower() in get_whitelisted_domains()
    except:
        return False
