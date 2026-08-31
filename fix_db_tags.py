import re

with open('backend/database.py', 'r') as f:
    content = f.read()

# 1. Add tags to CREATE TABLE cases
content = content.replace(
    'full_analysis_json TEXT,\n        analyzed_at',
    'full_analysis_json TEXT,\n        tags TEXT DEFAULT \'[]\',\n        analyzed_at'
)

# 2. Add tags to Safe column migrations for cases
content = content.replace(
    '("description", "TEXT"),',
    '("description", "TEXT"),\n        ("tags", "TEXT DEFAULT \'[]\'"),'
)

# 3. Add tags to save_case INSERT
content = content.replace(
    'anomalies_detected, analyst_notes, full_analysis_json,\n        analyzed_at',
    'anomalies_detected, analyst_notes, full_analysis_json, tags,\n        analyzed_at'
)
content = content.replace(
    ', ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)',
    ', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)'
)
content = content.replace(
    'json.dumps(case_data, cls=NumpySafeEncoder)\n    ))',
    'json.dumps(case_data, cls=NumpySafeEncoder),\n        json.dumps(case_data.get("tags", []))\n    ))'
)

with open('backend/database.py', 'w') as f:
    f.write(content)
