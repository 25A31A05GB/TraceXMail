with open('backend/main.py', 'r') as f:
    content = f.read()

content = content.replace(
    'class UpdateCaseRequest(BaseModel):\n    status: Optional[str] = None',
    'class UpdateCaseRequest(BaseModel):\n    status: Optional[str] = None\n    tags: Optional[List[str]] = None'
)

# And in update_case_endpoint:
replacement = """    if body.severity is not None:
        updates["severity"] = body.severity
    if body.tags is not None:
        updates["tags"] = body.tags
"""
content = content.replace(
    '    if body.severity is not None:\n        updates["severity"] = body.severity\n',
    replacement
)

with open('backend/main.py', 'w') as f:
    f.write(content)
