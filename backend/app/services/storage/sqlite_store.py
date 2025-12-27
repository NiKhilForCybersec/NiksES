"""
NiksES SQLite Analysis Store

Persistent storage for email analyses using SQLite.
"""

import json
import logging
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from collections import Counter, defaultdict

from app.models.analysis import AnalysisResult, AnalysisSummary

logger = logging.getLogger(__name__)

# Default database path
DEFAULT_DB_PATH = Path(__file__).parent.parent.parent.parent / "data" / "analyses.db"


class SQLiteAnalysisStore:
    """
    SQLite-based persistent analysis storage.
    
    Stores complete analysis results with full-text search capabilities.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path or DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection with row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn
    
    def _init_db(self):
        """Initialize database schema."""
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS analyses (
                    analysis_id TEXT PRIMARY KEY,
                    analyzed_at TIMESTAMP NOT NULL,
                    analysis_duration_ms INTEGER,
                    
                    -- Email metadata (for quick filtering)
                    subject TEXT,
                    sender_email TEXT,
                    sender_domain TEXT,
                    recipient_email TEXT,
                    message_id TEXT,
                    
                    -- Detection results (for quick filtering)
                    risk_score INTEGER NOT NULL,
                    risk_level TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    rules_triggered_count INTEGER DEFAULT 0,
                    
                    -- Counts
                    attachment_count INTEGER DEFAULT 0,
                    url_count INTEGER DEFAULT 0,
                    
                    -- AI Summary (for display)
                    ai_summary TEXT,
                    
                    -- Full JSON data
                    full_data TEXT NOT NULL,
                    
                    -- Timestamps
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                
                -- Indexes for common queries
                CREATE INDEX IF NOT EXISTS idx_analyzed_at ON analyses(analyzed_at DESC);
                CREATE INDEX IF NOT EXISTS idx_risk_score ON analyses(risk_score DESC);
                CREATE INDEX IF NOT EXISTS idx_risk_level ON analyses(risk_level);
                CREATE INDEX IF NOT EXISTS idx_classification ON analyses(classification);
                CREATE INDEX IF NOT EXISTS idx_sender_domain ON analyses(sender_domain);
                CREATE INDEX IF NOT EXISTS idx_sender_email ON analyses(sender_email);
                
                -- Full-text search on subject
                CREATE VIRTUAL TABLE IF NOT EXISTS analyses_fts USING fts5(
                    analysis_id,
                    subject,
                    sender_email,
                    content='analyses',
                    content_rowid='rowid'
                );
                
                -- Triggers to keep FTS in sync
                CREATE TRIGGER IF NOT EXISTS analyses_ai AFTER INSERT ON analyses BEGIN
                    INSERT INTO analyses_fts(rowid, analysis_id, subject, sender_email)
                    VALUES (new.rowid, new.analysis_id, new.subject, new.sender_email);
                END;
                
                CREATE TRIGGER IF NOT EXISTS analyses_ad AFTER DELETE ON analyses BEGIN
                    INSERT INTO analyses_fts(analyses_fts, rowid, analysis_id, subject, sender_email)
                    VALUES ('delete', old.rowid, old.analysis_id, old.subject, old.sender_email);
                END;
            """)
            conn.commit()
            logger.info(f"SQLite database initialized at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to initialize database: {e}")
            raise
        finally:
            conn.close()
    
    async def save(self, analysis: AnalysisResult) -> bool:
        """
        Save an analysis to the database.
        
        Args:
            analysis: Complete analysis result
            
        Returns:
            True if saved successfully
        """
        conn = self._get_connection()
        try:
            # Extract metadata for quick filtering
            email = analysis.email
            detection = analysis.detection
            
            sender_email = email.sender.email if email.sender else None
            sender_domain = email.sender.domain if email.sender else None
            recipient_email = email.to_recipients[0].email if email.to_recipients else None
            
            ai_summary = None
            if analysis.ai_triage:
                ai_summary = analysis.ai_triage.summary
            
            # Use unified score fields if available, otherwise fall back to detection
            # This ensures the correct multi-dimensional score is saved
            risk_score = analysis.overall_score if analysis.overall_score is not None else detection.risk_score
            risk_level = analysis.overall_level if analysis.overall_level else (
                detection.risk_level.value if hasattr(detection.risk_level, 'value') else str(detection.risk_level)
            )
            classification = analysis.classification if analysis.classification else (
                detection.primary_classification.value if hasattr(detection.primary_classification, 'value') else str(detection.primary_classification)
            )
            
            # Serialize full data
            full_data = analysis.model_dump_json()
            
            conn.execute("""
                INSERT OR REPLACE INTO analyses (
                    analysis_id, analyzed_at, analysis_duration_ms,
                    subject, sender_email, sender_domain, recipient_email, message_id,
                    risk_score, risk_level, classification, rules_triggered_count,
                    attachment_count, url_count, ai_summary, full_data, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (
                analysis.analysis_id,
                analysis.analyzed_at.isoformat(),
                analysis.analysis_duration_ms,
                email.subject,
                sender_email,
                sender_domain,
                recipient_email,
                email.message_id,
                risk_score,
                risk_level,
                classification,
                len(detection.rules_triggered),
                len(email.attachments),
                len(email.urls),
                ai_summary,
                full_data,
            ))
            conn.commit()
            logger.info(f"Saved analysis {analysis.analysis_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to save analysis: {e}")
            return False
        finally:
            conn.close()
    
    async def get(self, analysis_id: str) -> Optional[AnalysisResult]:
        """
        Get an analysis by ID.
        
        Args:
            analysis_id: Analysis identifier
            
        Returns:
            AnalysisResult or None if not found
        """
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "SELECT full_data FROM analyses WHERE analysis_id = ?",
                (analysis_id,)
            )
            row = cursor.fetchone()
            
            if row:
                return AnalysisResult.model_validate_json(row['full_data'])
            return None
            
        except Exception as e:
            logger.error(f"Failed to get analysis {analysis_id}: {e}")
            return None
        finally:
            conn.close()
    
    async def list(
        self,
        page: int = 1,
        page_size: int = 20,
        risk_level: Optional[str] = None,
        classification: Optional[str] = None,
        sender_domain: Optional[str] = None,
        search: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        sort_by: str = "analyzed_at",
        sort_order: str = "desc",
    ) -> Tuple[List[AnalysisSummary], int]:
        """
        List analyses with filtering and pagination.
        
        Returns:
            Tuple of (list of summaries, total count)
        """
        conn = self._get_connection()
        try:
            # Build query
            conditions = []
            params = []
            
            if risk_level:
                conditions.append("risk_level = ?")
                params.append(risk_level)
            
            if classification:
                conditions.append("classification = ?")
                params.append(classification)
            
            if sender_domain:
                conditions.append("sender_domain LIKE ?")
                params.append(f"%{sender_domain}%")
            
            if date_from:
                conditions.append("analyzed_at >= ?")
                params.append(date_from.isoformat())
            
            if date_to:
                conditions.append("analyzed_at <= ?")
                params.append(date_to.isoformat())
            
            # Handle search with FTS
            if search:
                conditions.append("""
                    analysis_id IN (
                        SELECT analysis_id FROM analyses_fts WHERE analyses_fts MATCH ?
                    )
                """)
                params.append(f"{search}*")
            
            where_clause = " AND ".join(conditions) if conditions else "1=1"
            
            # Validate sort
            allowed_sorts = ["analyzed_at", "risk_score", "subject", "sender_email"]
            if sort_by not in allowed_sorts:
                sort_by = "analyzed_at"
            sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"
            
            # Get total count
            count_query = f"SELECT COUNT(*) FROM analyses WHERE {where_clause}"
            cursor = conn.execute(count_query, params)
            total = cursor.fetchone()[0]
            
            # Get paginated results
            offset = (page - 1) * page_size
            query = f"""
                SELECT 
                    analysis_id, analyzed_at, subject, sender_email, sender_domain,
                    risk_score, risk_level, classification,
                    attachment_count, url_count, ai_summary
                FROM analyses
                WHERE {where_clause}
                ORDER BY {sort_by} {sort_order}
                LIMIT ? OFFSET ?
            """
            params.extend([page_size, offset])
            
            cursor = conn.execute(query, params)
            rows = cursor.fetchall()
            
            summaries = []
            for row in rows:
                summaries.append(AnalysisSummary(
                    analysis_id=row['analysis_id'],
                    analyzed_at=datetime.fromisoformat(row['analyzed_at']),
                    subject=row['subject'],
                    sender_email=row['sender_email'],
                    sender_domain=row['sender_domain'],
                    risk_score=row['risk_score'],
                    risk_level=row['risk_level'],
                    classification=row['classification'],
                    has_attachments=row['attachment_count'] > 0,
                    has_urls=row['url_count'] > 0,
                    attachment_count=row['attachment_count'],
                    url_count=row['url_count'],
                    ai_summary=row['ai_summary'],
                ))
            
            return summaries, total
            
        except Exception as e:
            logger.error(f"Failed to list analyses: {e}")
            return [], 0
        finally:
            conn.close()
    
    async def delete(self, analysis_id: str) -> bool:
        """Delete an analysis."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM analyses WHERE analysis_id = ?",
                (analysis_id,)
            )
            conn.commit()
            deleted = cursor.rowcount > 0
            if deleted:
                logger.info(f"Deleted analysis {analysis_id}")
            return deleted
        except Exception as e:
            logger.error(f"Failed to delete analysis {analysis_id}: {e}")
            return False
        finally:
            conn.close()
    
    async def delete_all(self) -> int:
        """Delete all analyses. Returns count deleted."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM analyses")
            count = cursor.fetchone()[0]
            conn.execute("DELETE FROM analyses")
            conn.commit()
            logger.info(f"Deleted all {count} analyses")
            return count
        except Exception as e:
            logger.error(f"Failed to delete all analyses: {e}")
            return 0
        finally:
            conn.close()
    
    async def get_stats(self, days: int = 7) -> Dict[str, Any]:
        """Get analysis statistics for dashboard."""
        conn = self._get_connection()
        try:
            cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            # Total count
            cursor = conn.execute(
                "SELECT COUNT(*) FROM analyses WHERE analyzed_at >= ?",
                (cutoff,)
            )
            total = cursor.fetchone()[0]
            
            # Risk distribution
            cursor = conn.execute("""
                SELECT risk_level, COUNT(*) as count
                FROM analyses
                WHERE analyzed_at >= ?
                GROUP BY risk_level
            """, (cutoff,))
            risk_dist = {row['risk_level']: row['count'] for row in cursor.fetchall()}
            
            # Classification distribution
            cursor = conn.execute("""
                SELECT classification, COUNT(*) as count
                FROM analyses
                WHERE analyzed_at >= ?
                GROUP BY classification
            """, (cutoff,))
            class_dist = {row['classification']: row['count'] for row in cursor.fetchall()}
            
            # Average risk score
            cursor = conn.execute(
                "SELECT AVG(risk_score) FROM analyses WHERE analyzed_at >= ?",
                (cutoff,)
            )
            avg_score = cursor.fetchone()[0] or 0
            
            # Top sender domains
            cursor = conn.execute("""
                SELECT sender_domain, COUNT(*) as count, AVG(risk_score) as avg_risk
                FROM analyses
                WHERE analyzed_at >= ? AND sender_domain IS NOT NULL
                GROUP BY sender_domain
                ORDER BY count DESC
                LIMIT 10
            """, (cutoff,))
            top_domains = [
                {"domain": row['sender_domain'], "count": row['count'], "avg_risk": round(row['avg_risk'], 1)}
                for row in cursor.fetchall()
            ]
            
            return {
                "total_analyses": total,
                "risk_distribution": risk_dist,
                "classification_distribution": class_dist,
                "average_risk_score": round(avg_score, 1),
                "top_sender_domains": top_domains,
                "period_days": days,
            }
            
        except Exception as e:
            logger.error(f"Failed to get stats: {e}")
            return {
                "total_analyses": 0,
                "risk_distribution": {},
                "classification_distribution": {},
                "average_risk_score": 0,
                "top_sender_domains": [],
                "period_days": days,
            }
        finally:
            conn.close()
    
    async def get_timeline(self, days: int = 7) -> List[Dict[str, Any]]:
        """Get timeline data for charts."""
        conn = self._get_connection()
        try:
            cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
            
            cursor = conn.execute("""
                SELECT 
                    DATE(analyzed_at) as date,
                    COUNT(*) as count,
                    AVG(risk_score) as avg_risk,
                    SUM(CASE WHEN risk_level = 'critical' THEN 1 ELSE 0 END) as critical_count,
                    SUM(CASE WHEN risk_level = 'high' THEN 1 ELSE 0 END) as high_count
                FROM analyses
                WHERE analyzed_at >= ?
                GROUP BY DATE(analyzed_at)
                ORDER BY date ASC
            """, (cutoff,))
            
            return [
                {
                    "date": row['date'],
                    "count": row['count'],
                    "average_risk_score": round(row['avg_risk'], 1),
                    "critical_count": row['critical_count'],
                    "high_count": row['high_count'],
                }
                for row in cursor.fetchall()
            ]
            
        except Exception as e:
            logger.error(f"Failed to get timeline: {e}")
            return []
        finally:
            conn.close()
    
    async def get_recent(self, limit: int = 10) -> List[AnalysisSummary]:
        """Get most recent analyses."""
        summaries, _ = await self.list(page=1, page_size=limit)
        return summaries
    
    def get_db_size(self) -> int:
        """Get database file size in bytes."""
        if self.db_path.exists():
            return self.db_path.stat().st_size
        return 0
    
    def get_analysis_count(self) -> int:
        """Get total number of analyses."""
        conn = self._get_connection()
        try:
            cursor = conn.execute("SELECT COUNT(*) FROM analyses")
            return cursor.fetchone()[0]
        finally:
            conn.close()


# Singleton instance
_sqlite_store: Optional[SQLiteAnalysisStore] = None


def get_sqlite_store(db_path: Optional[Path] = None) -> SQLiteAnalysisStore:
    """Get or create SQLite store singleton."""
    global _sqlite_store
    if _sqlite_store is None:
        _sqlite_store = SQLiteAnalysisStore(db_path)
    return _sqlite_store
