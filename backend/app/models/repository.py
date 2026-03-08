from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String

from app.db import Base


class Repository(Base):
    __tablename__ = "repositories"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, nullable=False)
    repo_url = Column(String, nullable=True)
    local_path = Column(String, nullable=True)
    ecosystem = Column(String, default="npm")
    language = Column(String, default="node")
    backboard_assistant_id = Column(String, nullable=True)
    backboard_depvuln_assistant_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
