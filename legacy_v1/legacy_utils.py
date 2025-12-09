import numpy as np
from urllib.parse import urlparse
import re
import socket

def extract_features_from_url(url):
    """
    Extract features from URL to match the UCI phishing dataset format.
    Returns a numpy array with 30 features matching the dataset columns.
    Includes DNS lookup to verify domain existence.
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        path = parsed_url.path
    except:
        # Return array of -1 if URL parsing fails (indicating suspicious)
        return np.full(30, -1)

    # Initialize features array with -1 (suspicious by default)
    features = np.full(30, -1)
    
    # 1. having_ip_address: 1 if IP address, -1 if domain name
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
        features[0] = 1
    else:
        features[0] = -1
    
    # 2. url_length: 1 if >= 75, -1 if < 54, 0 otherwise
    if len(url) >= 75:
        features[1] = 1
    elif len(url) < 54:
        features[1] = -1
    else:
        features[1] = 0
    
    # 3. shortining_service: 1 if shortening service, -1 if not
    shortening_services = ['bit.ly', 't.co', 'goo.gl', 'tinyurl', 'short.ly', 'ow.ly', 'is.gd']
    if any(service in hostname for service in shortening_services):
        features[2] = 1
    else:
        features[2] = -1
    
    # 4. having_at_symbol: 1 if @ in URL, -1 if not
    features[3] = 1 if '@' in url else -1
    
    # 5. double_slash_redirecting: 1 if // after protocol, -1 if not
    features[4] = 1 if url.rfind('//') > 7 else -1
    
    # 6. prefix_suffix: 1 if - in hostname, -1 if not
    features[5] = 1 if '-' in hostname else -1
    
    # 7. having_sub_domain: 1 if subdomain count > 2, -1 if not
    subdomain_count = hostname.count('.') - 1
    features[6] = 1 if subdomain_count > 2 else -1
    
    # 8. sslfinal_state: 1 if https, -1 if http
    features[7] = 1 if parsed_url.scheme == 'https' else -1
    
    # 9. domain_registration_length: 1 if TLD length > 4, -1 if not
    tld = hostname.split('.')[-1] if '.' in hostname else ''
    features[8] = 1 if len(tld) > 4 else -1
    
    # 10. favicon: -1 (cannot determine from URL alone)
    features[9] = -1
    
    # 11. port: 1 if non-standard port, -1 if standard
    port = parsed_url.port
    if port and port not in [80, 443, 8080]:
        features[10] = 1
    else:
        features[10] = -1
    
    # 12. https_token: 1 if https in domain, -1 if not
    features[11] = 1 if 'https' in hostname else -1
    
    # 13. request_url: -1 (cannot determine from URL alone)
    features[12] = -1
    
    # 14. url_of_anchor: -1 (cannot determine from URL alone)
    features[13] = -1
    
    # 15. links_in_tags: -1 (cannot determine from URL alone)
    features[14] = -1
    
    # 16. sfh: -1 (cannot determine from URL alone)
    features[15] = -1
    
    # 17. submitting_to_email: -1 (cannot determine from URL alone)
    features[16] = -1
    
    # 18. abnormal_url: 1 if suspicious patterns, -1 if normal
    suspicious_patterns = ['login', 'verify', 'account', 'update', 'secure', 'bank']
    features[17] = 1 if any(pattern in url.lower() for pattern in suspicious_patterns) else -1
    
    # 19. redirect: -1 (cannot determine from URL alone)
    features[18] = -1
    
    # 20. on_mouseover: -1 (cannot determine from URL alone)
    features[19] = -1
    
    # 21. rightclick: -1 (cannot determine from URL alone)
    features[20] = -1
    
    # 22. popupwindow: -1 (cannot determine from URL alone)
    features[21] = -1
    
    # 23. iframe: -1 (cannot determine from URL alone)
    features[22] = -1
    
    # 24. age_of_domain: -1
    features[23] = -1
    
    # 25. dnsrecord: 1 if no DNS record found (phishing), -1 if found (legitimate)
    # This is a key check for "incorrect" or non-existent URLs
    try:
        if hostname:
            socket.gethostbyname(hostname)
            features[24] = -1  # Legitimate/Exists
        else:
            features[24] = 1   # No hostname -> Suspicious
    except socket.error:
        features[24] = 1      # DNS resolution failed -> Phishing/Invalid
    
    # 26. web_traffic: -1 (cannot determine from URL alone)
    features[25] = -1
    
    # 27. page_rank: -1 (cannot determine from URL alone)
    features[26] = -1
    
    # 28. google_index: -1 (cannot determine from URL alone)
    features[27] = -1
    
    # 29. links_pointing_to_page: -1 (cannot determine from URL alone)
    features[28] = -1
    
    # 30. statistical_report: -1 (cannot determine from URL alone)
    features[29] = -1
    
    return features

def is_domain_active(url):
    """
    Checks if a domain is active by querying DNS records (A or MX).
    Returns True if active, False otherwise.
    Timeout set to 2 seconds to prevent freezing.
    """
    try:
        # Extract hostname
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Handle cases where URL might not have scheme (e.g. google.com)
        if not hostname:
             # Try parsing as if it was just a domain
             path = parsed_url.path
             if '/' in path:
                 hostname = path.split('/')[0]
             else:
                 hostname = path

        if not hostname:
            return False

        # Remove port if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]

        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        # Use Google DNS to ensure reliability
        resolver.nameservers = ['8.8.8.8', '8.8.4.4']

        # Try A record first
        try:
            resolver.resolve(hostname, 'A')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            pass
            
        # Try MX record as backup
        try:
            resolver.resolve(hostname, 'MX')
            return True
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
            # Final fallback: use standard socket
            try:
                socket.gethostbyname(hostname)
                return True
            except:
                return False
            
    except Exception:
        return False
