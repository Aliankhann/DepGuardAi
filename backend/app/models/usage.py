from sqlalchemy import Column, ForeignKey, Integer, JSON, String

from app.db import Base


class UsageLocation(Base):
    __tablename__ = "usage_locations"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id"), nullable=False)
    file_path = Column(String, nullable=False)
    line_number = Column(Integer, nullable=False)
    snippet = Column(String, nullable=False)
    import_type = Column(String, default="esm")  # esm | cjs | symbol | python
    context_tags = Column(JSON, default=list)
