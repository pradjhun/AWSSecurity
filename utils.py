from datetime import datetime, timezone
import pandas as pd
import json

def format_timestamp(timestamp, format_str='%Y-%m-%d %H:%M:%S'):
    """Format timestamp for display"""
    try:
        if isinstance(timestamp, str):
            # Try to parse string timestamp
            timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        
        if hasattr(timestamp, 'replace') and timestamp.tzinfo is not None:
            # Convert to local time for display
            timestamp = timestamp.replace(tzinfo=None)
        
        return timestamp.strftime(format_str)
    except Exception:
        return str(timestamp) if timestamp else 'N/A'

def calculate_security_score(overview_data):
    """Calculate overall security score based on various factors"""
    try:
        score = 100  # Start with perfect score
        
        # Deduct points for security issues
        critical_alerts = overview_data.get('critical_alerts', 0)
        score -= min(critical_alerts * 10, 50)  # Max 50 points deduction
        
        # Consider other factors (simplified calculation)
        iam_users = overview_data.get('iam_users', 0)
        if iam_users > 20:  # Too many users might indicate poor management
            score -= 5
        
        security_groups = overview_data.get('security_groups', 0)
        if security_groups > 50:  # Too many security groups
            score -= 5
        
        # Ensure score doesn't go below 0
        return max(score, 0)
    except Exception:
        return 85  # Default score if calculation fails

def get_severity_color(severity):
    """Get color code for severity level"""
    colors = {
        'CRITICAL': '#d62728',
        'HIGH': '#ff7f0e', 
        'MEDIUM': '#ffbb78',
        'LOW': '#2ca02c',
        'INFO': '#17a2b8'
    }
    return colors.get(severity.upper(), '#6c757d')

def format_bytes(bytes_value):
    """Format bytes into human readable format"""
    try:
        bytes_value = float(bytes_value)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.1f} PB"
    except (ValueError, TypeError):
        return "N/A"

def safe_get(dictionary, keys, default=None):
    """Safely get nested dictionary values"""
    try:
        result = dictionary
        for key in keys.split('.'):
            if isinstance(result, dict) and key in result:
                result = result[key]
            else:
                return default
        return result
    except Exception:
        return default

def validate_aws_region(region):
    """Validate AWS region format"""
    import re
    pattern = r'^[a-z0-9\-]+$'
    return bool(re.match(pattern, region)) if region else False

def sanitize_string(input_string, max_length=100):
    """Sanitize string for display"""
    try:
        if not input_string:
            return 'N/A'
        
        # Remove any potentially harmful characters
        sanitized = str(input_string).strip()
        
        # Truncate if too long
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length-3] + '...'
        
        return sanitized
    except Exception:
        return 'N/A'

def parse_aws_arn(arn):
    """Parse AWS ARN into components"""
    try:
        if not arn or not arn.startswith('arn:'):
            return None
        
        parts = arn.split(':')
        if len(parts) < 6:
            return None
        
        return {
            'partition': parts[1],
            'service': parts[2],
            'region': parts[3],
            'account_id': parts[4],
            'resource_type': parts[5].split('/')[0] if '/' in parts[5] else parts[5],
            'resource_id': parts[5].split('/', 1)[1] if '/' in parts[5] else ''
        }
    except Exception:
        return None

def format_duration(seconds):
    """Format duration in seconds to human readable format"""
    try:
        seconds = int(seconds)
        days = seconds // 86400
        hours = (seconds % 86400) // 3600
        minutes = (seconds % 3600) // 60
        seconds = seconds % 60
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
        
        return " ".join(parts)
    except (ValueError, TypeError):
        return "N/A"

def export_to_csv(data, filename):
    """Export data to CSV format"""
    try:
        if isinstance(data, list) and data:
            df = pd.DataFrame(data)
            return df.to_csv(index=False)
        elif isinstance(data, dict):
            df = pd.DataFrame([data])
            return df.to_csv(index=False)
        else:
            return "No data to export"
    except Exception as e:
        return f"Error exporting data: {str(e)}"

def export_to_json(data, indent=2):
    """Export data to JSON format"""
    try:
        return json.dumps(data, indent=indent, default=str)
    except Exception as e:
        return f"Error exporting data: {str(e)}"

def calculate_percentage(part, total):
    """Calculate percentage safely"""
    try:
        if total == 0:
            return 0
        return round((part / total) * 100, 1)
    except (ValueError, TypeError, ZeroDivisionError):
        return 0

def get_time_range_filter(days=7):
    """Get time range filter for queries"""
    try:
        end_time = datetime.utcnow()
        start_time = end_time - pd.Timedelta(days=days)
        return start_time, end_time
    except Exception:
        # Fallback to basic datetime
        from datetime import timedelta
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(days=days)
        return start_time, end_time

def mask_sensitive_data(data, fields_to_mask=None):
    """Mask sensitive data fields"""
    if fields_to_mask is None:
        fields_to_mask = ['password', 'secret', 'key', 'token', 'credential']
    
    try:
        if isinstance(data, dict):
            masked_data = {}
            for key, value in data.items():
                if any(field in key.lower() for field in fields_to_mask):
                    masked_data[key] = '*' * 8
                elif isinstance(value, (dict, list)):
                    masked_data[key] = mask_sensitive_data(value, fields_to_mask)
                else:
                    masked_data[key] = value
            return masked_data
        elif isinstance(data, list):
            return [mask_sensitive_data(item, fields_to_mask) for item in data]
        else:
            return data
    except Exception:
        return data

def validate_ip_address(ip):
    """Validate IP address format"""
    try:
        import ipaddress
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def get_risk_level(score):
    """Get risk level based on score"""
    try:
        score = float(score)
        if score >= 90:
            return 'Low'
        elif score >= 70:
            return 'Medium'
        elif score >= 50:
            return 'High'
        else:
            return 'Critical'
    except (ValueError, TypeError):
        return 'Unknown'

def format_error_message(error, context=""):
    """Format error message for user display"""
    try:
        if hasattr(error, 'response') and hasattr(error.response, 'get'):
            # AWS API error
            error_code = error.response.get('Error', {}).get('Code', 'Unknown')
            error_message = error.response.get('Error', {}).get('Message', str(error))
            return f"AWS Error ({error_code}): {error_message}"
        else:
            # Generic error
            error_str = str(error)
            if context:
                return f"Error in {context}: {error_str}"
            return f"Error: {error_str}"
    except Exception:
        return f"An unexpected error occurred: {str(error)}"
