import re

with open('backend/database.py', 'r') as f:
    content = f.read()

def replace_get_all(match):
    return """        if r.get("tags"):
            try:
                r["tags"] = json.loads(r["tags"])
            except:
                r["tags"] = []
        else:
            r["tags"] = []
""" + match.group(0).replace(
    '["status", "severity", "title", "analyst_notes", "organization_id", "analyzed_at", "updated_at"]',
    '["status", "severity", "title", "analyst_notes", "organization_id", "analyzed_at", "updated_at", "tags"]'
)

content = re.sub(r'        if r\.get\("full_analysis_json"\):.*?except Exception:\n                pass', replace_get_all, content, flags=re.DOTALL)

def replace_get_by_id(match):
    return """    if row_dict.get("tags"):
        try:
            row_dict["tags"] = json.loads(row_dict["tags"])
        except:
            row_dict["tags"] = []
    else:
        row_dict["tags"] = []

""" + match.group(0).replace(
    'if "updated_at" in row_dict and row_dict["updated_at"]:\n                full["updated_at"] = str(row_dict["updated_at"])',
    'if "updated_at" in row_dict and row_dict["updated_at"]:\n                full["updated_at"] = str(row_dict["updated_at"])\n            if "tags" in row_dict:\n                full["tags"] = row_dict["tags"]'
)

content = re.sub(r'    if row_dict\.get\("full_analysis_json"\):.*?except Exception:\n            pass', replace_get_by_id, content, flags=re.DOTALL)

with open('backend/database.py', 'w') as f:
    f.write(content)
