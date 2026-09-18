import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.rate_limiter import AdaptiveRateLimiter, TokenBucket


def test_token_bucket_starts_full():
    bucket = TokenBucket(rps=10.0)
    assert bucket.tokens == 10.0


@pytest.mark.asyncio
async def test_token_bucket_acquire_consumes_token():
    bucket = TokenBucket(rps=10.0)
    await bucket.acquire()
    assert bucket.tokens < 10.0


def test_on_response_429_halves_rps():
    limiter = AdaptiveRateLimiter(default_rps=10.0, min_rps=1.0, backoff_multiplier=2.0)
    limiter._get_bucket("example.com")
    limiter.on_response("example.com", 429)
    assert limiter._buckets["example.com"].rps == 5.0


def test_on_response_429_respects_min_rps():
    limiter = AdaptiveRateLimiter(default_rps=1.0, min_rps=1.0, backoff_multiplier=2.0)
    limiter._get_bucket("example.com")
    limiter.on_response("example.com", 429)
    assert limiter._buckets["example.com"].rps == 1.0


def test_on_response_503_pauses_domain():
    limiter = AdaptiveRateLimiter(pause_on_503=30)
    limiter.on_response("example.com", 503)
    assert "example.com" in limiter._paused_until


def test_on_response_success_streak_increases_rps():
    limiter = AdaptiveRateLimiter(default_rps=10.0, max_rps=50.0)
    for _ in range(20):
        limiter.on_response("example.com", 200)
    assert limiter._buckets["example.com"].rps > 10.0


def test_get_stats_reports_domain():
    limiter = AdaptiveRateLimiter()
    limiter._get_bucket("example.com")
    stats = limiter.get_stats()
    assert "example.com" in stats
    assert stats["example.com"]["paused"] is False
