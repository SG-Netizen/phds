"""
PHDS API 限流中间件

基于 IP 的滑动窗口限流：
  - 默认每分钟 60 次
  - 超限返回 429 Too Many Requests
  - 使用内存字典存储，进程重启后重置
"""
from __future__ import annotations

import time
from collections import defaultdict
from typing import DefaultDict, List

from fastapi import Request
from starlette.responses import JSONResponse


class SlidingWindowRateLimiter:
    """基于 IP 的滑动窗口限流器。

    每个 IP 维护一个请求时间戳列表，每次请求时清理窗口外的旧记录，
    然后判断窗口内请求数是否超限。

    Attributes:
        max_requests:   窗口内最大请求数
        window_seconds: 窗口时长（秒）
    """

    def __init__(self, max_requests: int = 60, window_seconds: int = 60) -> None:
        """初始化限流器。

        Args:
            max_requests:   窗口内最大请求数，默认 60
            window_seconds: 滑动窗口时长（秒），默认 60
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        # IP → 请求时间戳列表（Unix 时间戳）
        self._clients: DefaultDict[str, List[float]] = defaultdict(list)

    def _clean_window(self, ip: str) -> None:
        """清理窗口外的过期记录。

        Args:
            ip: 客户端 IP 地址
        """
        now = time.time()
        cutoff = now - self.window_seconds
        self._clients[ip] = [t for t in self._clients[ip] if t > cutoff]

    def is_allowed(self, ip: str) -> bool:
        """检查指定 IP 是否允许本次请求。

        Args:
            ip: 客户端 IP 地址

        Returns:
            True 表示允许，False 表示超限
        """
        self._clean_window(ip)
        if len(self._clients[ip]) >= self.max_requests:
            return False
        self._clients[ip].append(time.time())
        return True

    def remaining(self, ip: str) -> int:
        """查询指定 IP 的剩余可用次数。

        Args:
            ip: 客户端 IP 地址

        Returns:
            剩余次数
        """
        self._clean_window(ip)
        return max(0, self.max_requests - len(self._clients[ip]))


def get_client_ip(request: Request) -> str:
    """从请求中提取客户端 IP。

    优先从 X-Forwarded-For / X-Real-IP 头获取，回退到 request.client.host。

    Args:
        request: FastAPI / Starlette Request 对象

    Returns:
        IP 地址字符串
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()
    if request.client:
        return request.client.host
    return "unknown"


# ── 默认限流器实例 ────────────────────────────────────────
_default_limiter = SlidingWindowRateLimiter(max_requests=60, window_seconds=60)


async def get_rate_limiter(request: Request) -> SlidingWindowRateLimiter:
    """FastAPI Depends 依赖函数：注入限流器并检查当前请求是否超限。

    用法::

        @app.get("/api/data")
        def get_data(limiter: SlidingWindowRateLimiter = Depends(get_rate_limiter)):
            ...

    超限时自动返回 429 响应。

    Args:
        request: FastAPI Request 对象

    Returns:
        SlidingWindowRateLimiter 实例

    Raises:
        HTTPException: 429 请求过于频繁
    """
    from fastapi import HTTPException
    ip = get_client_ip(request)
    if not _default_limiter.is_allowed(ip):
        raise HTTPException(status_code=429, detail="请求过于频繁，请稍后重试")
    return _default_limiter


async def rate_limit_middleware(request: Request, call_next):
    """ASGI 限流中间件。

    对每个请求检查 IP 是否超限，超限则返回 429 JSON 响应。

    Args:
        request:   Starlette Request 对象
        call_next: 下一个 ASGI 应用

    Returns:
        Response 对象
    """
    ip = get_client_ip(request)
    if not _default_limiter.is_allowed(ip):
        return JSONResponse(
            status_code=429,
            content={"detail": "请求过于频繁，请稍后重试"},
        )
    response = await call_next(request)
    return response
