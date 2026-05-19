from __future__ import annotations

import inspect
from contextvars import copy_context


def submit_with_current_context(executor, fn, *args, **kwargs):
    return executor.submit(copy_context().run, fn, *args, **kwargs)


async def submit_with_current_context_async(fn, *args, **kwargs):
    result = copy_context().run(fn, *args, **kwargs)
    if inspect.isawaitable(result):
        return await result
    return result
