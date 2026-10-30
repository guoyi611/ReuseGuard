"""Adapters around external data sources and tools.

Each adapter is intentionally thin: it translates a third-party response into
ReuseGuard's internal models and raises a typed error for the pipeline to turn
into a warning or an ``unknown`` result.
"""
