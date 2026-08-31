with open('backend/models.py', 'r') as f:
    content = f.read()

content = content.replace(
    '    description = Column(Text, nullable=True)',
    '    description = Column(Text, nullable=True)\n    tags = Column(JSON, default=list, nullable=True)'
)

with open('backend/models.py', 'w') as f:
    f.write(content)
