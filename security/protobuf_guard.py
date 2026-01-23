from google.protobuf import json_format

MAX_JSON_DEPTH = 50

def _max_depth(obj, depth=0):
    if not isinstance(obj, (dict, list)):
        return depth
    if isinstance(obj, dict):
        return max([_max_depth(v, depth + 1) for v in obj.values()] + [depth])
    return max([_max_depth(v, depth + 1) for v in obj] + [depth])

def safe_parse_dict(payload, message, *args, **kwargs):
    if _max_depth(payload) > MAX_JSON_DEPTH:
        raise ValueError("Rejected protobuf JSON: nesting depth exceeded")
    return json_format.ParseDict(payload, message, *args, **kwargs)
