from sqlalchemy import Column, ForeignKey, Integer, String

from app.db import Base


class Dependency(Base):
    __tablename__ = "dependencies"

    id = Column(Integer, primary_key=True, index=True)
    repo_id = Column(Integer, ForeignKey("repositories.id"), nullable=False)
    scan_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    name = Column(String, nullable=False)
    version = Column(String, nullable=False)
    ecosystem = Column(String, default="npm")
