import re

with open('/tmp/database_original.py', 'r') as f:
    content = f.read()

# Fix 1: PRAGMA journal_mode and PRAGMA quick_check
# Make sure they are guarded by if IS_SQLITE:
content = re.sub(
    r'(conn\.execute\("PRAGMA journal_mode=WAL;"\)\s+conn\.execute\("PRAGMA quick_check;"\))',
    r'if IS_SQLITE:\n            \1',
    content
)

# Fix 2: ALTER TABLE statements
content = content.replace(
    'try:\n            cursor.execute(f"ALTER TABLE emails ADD COLUMN {col_def[0]} {col_def[1]}")\n        except Exception:\n            pass',
    'try:\n            cursor.execute(f"ALTER TABLE emails ADD COLUMN {col_def[0]} {col_def[1]}")\n            conn.commit()\n        except Exception as e:\n            conn.rollback()'
)

content = content.replace(
    'try:\n            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_def[0]} {col_def[1]}")\n        except Exception:\n            pass',
    'try:\n            cursor.execute(f"ALTER TABLE evidence ADD COLUMN {col_def[0]} {col_def[1]}")\n            conn.commit()\n        except Exception as e:\n            conn.rollback()'
)

content = content.replace(
    'try:\n            cursor.execute(f"ALTER TABLE cases ADD COLUMN {col_def[0]} {col_def[1]}")\n        except Exception:\n            pass',
    'try:\n            cursor.execute(f"ALTER TABLE cases ADD COLUMN {col_def[0]} {col_def[1]}")\n            conn.commit()\n        except Exception as e:\n            conn.rollback()'
)

content = content.replace(
    'try:\n            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_def[0]} {col_def[1]}")\n        except Exception:\n            pass',
    'try:\n            cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_def[0]} {col_def[1]}")\n            conn.commit()\n        except Exception as e:\n            conn.rollback()'
)

content = content.replace(
    'try:\n            cursor.execute(f"ALTER TABLE retention_jobs ADD COLUMN {col_def[0]} {col_def[1]}")\n        except Exception:\n            pass',
    'try:\n            cursor.execute(f"ALTER TABLE retention_jobs ADD COLUMN {col_def[0]} {col_def[1]}")\n            conn.commit()\n        except Exception as e:\n            conn.rollback()'
)

def replace_create_table(match):
    statement = match.group(1)
    return f"""try:
        cursor.execute(\"\"\"{statement}\"\"\")
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on table creation: {{e}}")
        conn.rollback()"""

content = re.sub(r'cursor\.execute\(\"\"\"(\n\s*CREATE TABLE.*?)\"\"\"\)', replace_create_table, content, flags=re.DOTALL)

def replace_insert(match):
    statement = match.group(1)
    return f"""try:
        cursor.execute(\"\"\"{statement}\"\"\")
        conn.commit()
    except Exception as e:
        print(f"[DB Init] Failed on default seed: {{e}}")
        conn.rollback()"""

content = re.sub(r'cursor\.execute\(\"\"\"(\n\s*INSERT OR IGNORE.*?)\"\"\"\)', replace_insert, content, flags=re.DOTALL)

with open('backend/database.py', 'w') as f:
    f.write(content)
