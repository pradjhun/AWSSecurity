"""
Cached version of SecurityMonitors for improved performance
Extends SecurityMonitors with database caching capabilities
"""

from security_monitors import SecurityMonitors
from cache_database import SecurityDataCache
import time
import json
from typing import Dict, Any, Optional

class CachedSecurityMonitors(SecurityMonitors):
    """SecurityMonitors with integrated caching for performance optimization"""
    
    def __init__(self, aws_client, cache: SecurityDataCache = None):
        super().__init__(aws_client)
        self.cache = cache or SecurityDataCache()
        
        # Cache TTL settings for different operations (in seconds)
        self.cache_ttl = {
            'security_overview': 180,       # 3 minutes
            'compliance_data': 300,         # 5 minutes
            'alerts_and_threats': 120,      # 2 minutes
            'threats_data': 120,            # 2 minutes
            'enhanced_findings': 600,       # 10 minutes
            'iam_security': 300,            # 5 minutes
            'network_security': 300,        # 5 minutes
            'data_protection': 600,         # 10 minutes
        }
    
    def _cached_operation(self, operation_name: str, operation_func, *args, **kwargs):
        """Execute operation with caching"""
        start_time = time.time()
        
        # Create cache key from operation and parameters
        cache_params = {
            'args': list(args),
            'kwargs': dict(kwargs)
        }
        
        region = getattr(self.aws_client, 'region_name', 'default')
        
        # Try cache first
        cached_result = self.cache.get(operation_name, cache_params, region)
        if cached_result is not None:
            return cached_result
        
        # Execute operation and cache result
        try:
            result = operation_func(*args, **kwargs)
            ttl = self.cache_ttl.get(operation_name, 300)
            self.cache.set(operation_name, result, cache_params, region, ttl)
            return result
        except Exception as e:
            # Don't cache errors, re-raise
            raise e
    
    def get_security_overview(self):
        """Cached security overview"""
        return self._cached_operation('security_overview', super().get_security_overview)
    
    def get_compliance_data(self):
        """Cached compliance data"""
        return self._cached_operation('compliance_data', super().get_compliance_data)
    
    def get_alerts_and_threats_data(self):
        """Cached alerts and threats data"""
        return self._cached_operation('alerts_and_threats', super().get_alerts_and_threats_data)
    
    def get_threats_data(self):
        """Cached threats data"""
        return self._cached_operation('threats_data', super().get_threats_data)
    
    def get_iam_security_data(self):
        """Cached IAM security data"""
        return self._cached_operation('iam_security', super().get_iam_security_data)
    
    def get_network_security_data(self):
        """Cached network security data"""
        return self._cached_operation('network_security', super().get_network_security_data)
    
    def get_data_protection_data(self):
        """Cached data protection data"""
        return self._cached_operation('data_protection', super().get_data_protection_data)
    
    def invalidate_cache(self, operation: str = None):
        """Invalidate cache for specific operation or all"""
        region = getattr(self.aws_client, 'region_name', 'default')
        return self.cache.invalidate(operation, region)
    
    def get_cache_performance_stats(self):
        """Get cache performance statistics"""
        return self.cache.get_performance_stats()