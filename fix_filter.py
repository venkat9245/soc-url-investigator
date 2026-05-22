import sys
sys.path.insert(0, '.')
import app_module = __import__('app')

def safe_from_json(v):
    import json
    if isinstance(v, dict):
        return v
    if isinstance(v, str) and v.strip():
        try:
            return json.loads(v)
        except:
            return {}
    return {}
