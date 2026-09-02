# Data models for Forensic Analysis, Cases, Campaigns, and Alerts

class Case:
    def __init__(self, id, title, description, severity, threat_score, status="OPEN"):
        self.id = id
        self.title = title
        self.description = description
        self.severity = severity
        self.threat_score = threat_score
        self.status = status
