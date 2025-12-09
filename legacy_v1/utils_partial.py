
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
            return False
            
    except Exception:
        return False
