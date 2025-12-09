import dns.resolver
from utils import is_domain_active

print("Checking Google.com with is_domain_active...")
try:
    result = is_domain_active("http://google.com")
    print(f"Result: {result}")
except Exception as e:
    print(f"Wrapper Exception: {e}")

print("\nDebug raw resolver:")
try:
    res = dns.resolver.Resolver()
    res.timeout = 5
    res.lifetime = 5
    print(f"Nameservers: {res.nameservers}")
    answer = res.resolve('google.com', 'A')
    print(f"Answer: {answer}")
    for rdata in answer:
        print(f" IP: {rdata}")
except Exception as e:
    print(f"Raw Exception: {e}")
