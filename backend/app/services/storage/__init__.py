"""
NiksES Storage Module

Provides persistent storage for analyses.
"""

from .sqlite_store import SQLiteAnalysisStore, get_sqlite_store

__all__ = ['SQLiteAnalysisStore', 'get_sqlite_store']
