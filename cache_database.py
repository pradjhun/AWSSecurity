"""
Lightweight SQLite database for caching AWS security data
Improves dashboard performance by reducing redundant API calls
"""

import sqlite3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
import hashlib
import os

class SecurityDataCache:
    """SQLite-based cache for AWS security data"""
    
    def __init__(self, db_path: str = "aws_security_cache.db"):
        self.db_path = db_path
        self.default_ttl = 300  # 5 minutes default TTL
        self.init_database()
    
    def init_database(self):
        """Initialize the cache database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Cache table for general AWS data
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS cache_data (
                key TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                region TEXT,
                data_type TEXT
            )
        """)
        
        # Performance metrics table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT NOT NULL,
                execution_time REAL NOT NULL,
                timestamp REAL NOT NULL,
                cache_hit BOOLEAN NOT NULL
            )
        """)
        
        # Index for faster lookups
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_expires ON cache_data(key, expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_data_type ON cache_data(data_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_region ON cache_data(region)")
        
        conn.commit()
        conn.close()
    
    def _generate_cache_key(self, operation: str, params: Dict[str, Any] = None, region: str = None) -> str:
        """Generate a unique cache key for the operation and parameters"""
        key_data = {
            'operation': operation,
            'params': params or {},
            'region': region
        }
        key_string = json.dumps(key_data, sort_keys=True)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def get(self, operation: str, params: Dict[str, Any] = None, region: str = None) -> Optional[Any]:
        """Retrieve data from cache if available and not expired"""
        start_time = time.time()
        cache_key = self._generate_cache_key(operation, params, region)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = time.time()
        cursor.execute(
            "SELECT data FROM cache_data WHERE key = ? AND expires_at > ?",
            (cache_key, current_time)
        )
        
        result = cursor.fetchone()
        conn.close()
        
        # Record performance metric
        execution_time = time.time() - start_time
        self._record_performance(operation, execution_time, cache_hit=(result is not None))
        
        if result:
            try:
                return json.loads(result[0])
            except json.JSONDecodeError:
                return None
        
        return None
    
    def set(self, operation: str, data: Any, params: Dict[str, Any] = None, 
            region: str = None, ttl: int = None) -> None:
        """Store data in cache with expiration"""
        cache_key = self._generate_cache_key(operation, params, region)
        ttl = ttl or self.default_ttl
        
        current_time = time.time()
        expires_at = current_time + ttl
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT OR REPLACE INTO cache_data 
            (key, data, created_at, expires_at, region, data_type)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            cache_key,
            json.dumps(data, default=str),
            current_time,
            expires_at,
            region,
            operation
        ))
        
        conn.commit()
        conn.close()
    
    def invalidate(self, operation: str = None, region: str = None) -> int:
        """Invalidate cache entries by operation or region"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if operation and region:
            cursor.execute("DELETE FROM cache_data WHERE data_type = ? AND region = ?", (operation, region))
        elif operation:
            cursor.execute("DELETE FROM cache_data WHERE data_type = ?", (operation,))
        elif region:
            cursor.execute("DELETE FROM cache_data WHERE region = ?", (region,))
        else:
            cursor.execute("DELETE FROM cache_data")
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
    
    def cleanup_expired(self) -> int:
        """Remove expired cache entries"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = time.time()
        cursor.execute("DELETE FROM cache_data WHERE expires_at <= ?", (current_time,))
        
        deleted_count = cursor.rowcount
        conn.commit()
        conn.close()
        
        return deleted_count
    
    def _record_performance(self, operation: str, execution_time: float, cache_hit: bool) -> None:
        """Record performance metrics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            INSERT INTO performance_metrics (operation, execution_time, timestamp, cache_hit)
            VALUES (?, ?, ?, ?)
        """, (operation, execution_time, time.time(), cache_hit))
        
        conn.commit()
        conn.close()
    
    def get_performance_stats(self, hours: int = 24) -> Dict[str, Any]:
        """Get performance statistics for the specified time period"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        since_time = time.time() - (hours * 3600)
        
        # Overall stats
        cursor.execute("""
            SELECT 
                COUNT(*) as total_operations,
                AVG(execution_time) as avg_time,
                SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) as cache_hits,
                AVG(CASE WHEN cache_hit THEN execution_time END) as avg_cache_time,
                AVG(CASE WHEN NOT cache_hit THEN execution_time END) as avg_api_time
            FROM performance_metrics 
            WHERE timestamp > ?
        """, (since_time,))
        
        overall_stats = cursor.fetchone()
        
        # Per-operation stats
        cursor.execute("""
            SELECT 
                operation,
                COUNT(*) as count,
                AVG(execution_time) as avg_time,
                SUM(CASE WHEN cache_hit THEN 1 ELSE 0 END) as cache_hits
            FROM performance_metrics 
            WHERE timestamp > ?
            GROUP BY operation
            ORDER BY count DESC
        """, (since_time,))
        
        operation_stats = cursor.fetchall()
        
        conn.close()
        
        if overall_stats[0] > 0:  # If we have data
            cache_hit_rate = (overall_stats[2] / overall_stats[0]) * 100 if overall_stats[0] > 0 else 0
            
            return {
                'total_operations': overall_stats[0],
                'average_time': overall_stats[1] or 0,
                'cache_hits': overall_stats[2],
                'cache_hit_rate': cache_hit_rate,
                'avg_cache_time': overall_stats[3] or 0,
                'avg_api_time': overall_stats[4] or 0,
                'operation_breakdown': [
                    {
                        'operation': op[0],
                        'count': op[1],
                        'avg_time': op[2],
                        'cache_hits': op[3],
                        'cache_hit_rate': (op[3] / op[1]) * 100 if op[1] > 0 else 0
                    }
                    for op in operation_stats
                ]
            }
        
        return {
            'total_operations': 0,
            'average_time': 0,
            'cache_hits': 0,
            'cache_hit_rate': 0,
            'avg_cache_time': 0,
            'avg_api_time': 0,
            'operation_breakdown': []
        }
    
    def get_cache_info(self) -> Dict[str, Any]:
        """Get cache information and statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        current_time = time.time()
        
        # Cache size and status
        cursor.execute("SELECT COUNT(*) FROM cache_data")
        total_entries = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cache_data WHERE expires_at > ?", (current_time,))
        active_entries = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM cache_data WHERE expires_at <= ?", (current_time,))
        expired_entries = cursor.fetchone()[0]
        
        # Data types breakdown
        cursor.execute("""
            SELECT data_type, COUNT(*) 
            FROM cache_data 
            WHERE expires_at > ?
            GROUP BY data_type
        """, (current_time,))
        
        data_types = dict(cursor.fetchall())
        
        # Region breakdown
        cursor.execute("""
            SELECT region, COUNT(*) 
            FROM cache_data 
            WHERE expires_at > ? AND region IS NOT NULL
            GROUP BY region
        """, (current_time,))
        
        regions = dict(cursor.fetchall())
        
        # Database size
        cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
        db_size = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'total_entries': total_entries,
            'active_entries': active_entries,
            'expired_entries': expired_entries,
            'data_types': data_types,
            'regions': regions,
            'database_size_bytes': db_size,
            'database_size_mb': db_size / (1024 * 1024)
        }


class CachedAWSClient:
    """Wrapper around AWSClient with caching capabilities"""
    
    def __init__(self, aws_client, cache: SecurityDataCache = None):
        self.aws_client = aws_client
        self.cache = cache or SecurityDataCache()
        
        # Cache TTL settings for different operations (in seconds)
        self.cache_ttl = {
            'list_iam_users': 600,          # 10 minutes
            'list_iam_roles': 600,          # 10 minutes
            'list_security_groups': 300,    # 5 minutes
            'list_s3_buckets': 900,         # 15 minutes
            'list_vpcs': 900,               # 15 minutes
            'get_account_id': 3600,         # 1 hour
            'describe_trails': 1800,        # 30 minutes
            'list_kms_keys': 1800,          # 30 minutes
            'overview_data': 180,           # 3 minutes
            'compliance_data': 300,         # 5 minutes
            'threats_data': 120,            # 2 minutes
            'guardduty_findings': 300,      # 5 minutes
        }
    
    def _cached_operation(self, operation_name: str, operation_func, *args, **kwargs):
        """Execute operation with caching"""
        # Create cache parameters from function arguments
        cache_params = {
            'args': args,
            'kwargs': kwargs
        }
        
        region = kwargs.get('region') or getattr(self.aws_client, 'region_name', None)
        
        # Try cache first
        cached_result = self.cache.get(operation_name, cache_params, region)
        if cached_result is not None:
            return cached_result
        
        # Execute operation and cache result
        try:
            result = operation_func(*args, **kwargs)
            ttl = self.cache_ttl.get(operation_name, self.cache.default_ttl)
            self.cache.set(operation_name, result, cache_params, region, ttl)
            return result
        except Exception as e:
            # Don't cache errors, re-raise
            raise e
    
    def list_iam_users(self):
        """Cached IAM users list"""
        return self._cached_operation('list_iam_users', self.aws_client.list_iam_users)
    
    def list_iam_roles(self):
        """Cached IAM roles list"""
        return self._cached_operation('list_iam_roles', self.aws_client.list_iam_roles)
    
    def list_security_groups(self):
        """Cached security groups list"""
        return self._cached_operation('list_security_groups', self.aws_client.list_security_groups)
    
    def list_s3_buckets(self):
        """Cached S3 buckets list"""
        return self._cached_operation('list_s3_buckets', self.aws_client.list_s3_buckets)
    
    def list_vpcs(self):
        """Cached VPCs list"""
        return self._cached_operation('list_vpcs', self.aws_client.list_vpcs)
    
    def get_account_id(self):
        """Cached account ID"""
        return self._cached_operation('get_account_id', self.aws_client.get_account_id)
    
    def describe_trails(self):
        """Cached CloudTrail trails"""
        return self._cached_operation('describe_trails', self.aws_client.describe_trails)
    
    def list_kms_keys(self):
        """Cached KMS keys"""
        return self._cached_operation('list_kms_keys', self.aws_client.list_kms_keys)
    
    def list_guardduty_detectors(self):
        """Cached GuardDuty detectors"""
        return self._cached_operation('list_guardduty_detectors', self.aws_client.list_guardduty_detectors)
    
    def list_guardduty_findings(self, detector_id, max_items=50):
        """Cached GuardDuty findings"""
        return self._cached_operation('list_guardduty_findings', 
                                     self.aws_client.list_guardduty_findings, 
                                     detector_id, max_items)
    
    def invalidate_cache(self, operation: str = None, region: str = None):
        """Invalidate cache entries"""
        return self.cache.invalidate(operation, region)
    
    def get_cache_stats(self):
        """Get cache performance statistics"""
        return self.cache.get_performance_stats()
    
    def get_cache_info(self):
        """Get cache information"""
        return self.cache.get_cache_info()
    
    def cleanup_cache(self):
        """Clean up expired cache entries"""
        return self.cache.cleanup_expired()


def show_cache_management_interface(cached_client: CachedAWSClient):
    """Streamlit interface for cache management"""
    import streamlit as st
    
    st.subheader("🗄️ Cache Management")
    
    # Cache statistics
    cache_stats = cached_client.get_cache_stats()
    cache_info = cached_client.get_cache_info()
    
    # Performance metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Operations", cache_stats['total_operations'])
    
    with col2:
        st.metric("Cache Hit Rate", f"{cache_stats['cache_hit_rate']:.1f}%")
    
    with col3:
        st.metric("Cache Entries", cache_info['active_entries'])
    
    with col4:
        st.metric("DB Size", f"{cache_info['database_size_mb']:.1f} MB")
    
    # Performance comparison
    if cache_stats['avg_cache_time'] > 0 and cache_stats['avg_api_time'] > 0:
        speed_improvement = ((cache_stats['avg_api_time'] - cache_stats['avg_cache_time']) / cache_stats['avg_api_time']) * 100
        st.success(f"Cache provides {speed_improvement:.1f}% speed improvement")
    
    # Cache controls with enhanced feedback
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        if st.button("🔄 Clear All Cache", type="primary", use_container_width=True, key="cache_mgmt_clear_all"):
            with st.spinner("Clearing cache..."):
                cleared = cached_client.invalidate_cache()
                if cleared > 0:
                    st.success(f"✅ Cleared {cleared} cache entries")
                    st.balloons()
                else:
                    st.info("Cache was already empty")
            st.rerun()
    
    with col2:
        if st.button("🧹 Clean Expired", use_container_width=True, key="cache_mgmt_clean_expired"):
            with st.spinner("Cleaning expired entries..."):
                cleaned = cached_client.cleanup_cache()
                if cleaned > 0:
                    st.success(f"🗑️ Cleaned {cleaned} expired entries")
                else:
                    st.info("No expired entries found")
    
    with col3:
        if st.button("⚡ Force Refresh", use_container_width=True, key="cache_mgmt_force_refresh"):
            with st.spinner("Forcing data refresh..."):
                # Clear cache and refresh immediately
                cleared = cached_client.invalidate_cache()
                st.success(f"🔄 Refreshed! Cleared {cleared} entries")
            st.rerun()
    
    with col4:
        if st.button("📊 Refresh Stats", use_container_width=True, key="cache_mgmt_refresh_stats"):
            st.rerun()
    
    # Detailed breakdown
    if cache_stats['operation_breakdown']:
        st.subheader("📈 Operation Performance")
        
        breakdown_data = []
        for op in cache_stats['operation_breakdown']:
            breakdown_data.append({
                'Operation': op['operation'],
                'Count': op['count'],
                'Avg Time (ms)': f"{op['avg_time']*1000:.1f}",
                'Cache Hits': op['cache_hits'],
                'Hit Rate (%)': f"{op['cache_hit_rate']:.1f}"
            })
        
        st.dataframe(breakdown_data, use_container_width=True)
    
    # Cache composition
    if cache_info['data_types']:
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("📋 Cache by Data Type")
            for data_type, count in cache_info['data_types'].items():
                st.write(f"**{data_type}:** {count} entries")
        
        with col2:
            if cache_info['regions']:
                st.subheader("🌍 Cache by Region")
                for region, count in cache_info['regions'].items():
                    st.write(f"**{region}:** {count} entries")