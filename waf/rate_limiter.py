from collections import defaultdict, deque
from time import time

hits = defaultdict(deque)

def is_rate_limited(ip, limit=10, window=10):
    now = time()
    q = hits[ip]
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    return len(q) > limit