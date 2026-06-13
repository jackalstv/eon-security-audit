from sqlalchemy import Column, String, Integer, DateTime, JSON, ForeignKey
from sqlalchemy.orm import relationship
from database import Base


class ScanRecord(Base):
    __tablename__ = "scans"

    scan_id = Column(String, primary_key=True)
    domain = Column(String, nullable=False, index=True)
    platform = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False)
    overall_score = Column(Integer, nullable=False)
    summary = Column(String, default="")
    critical_issues = Column(Integer, default=0)
    high_issues = Column(Integer, default=0)
    medium_issues = Column(Integer, default=0)
    low_issues = Column(Integer, default=0)

    modules = relationship("ModuleRecord", back_populates="scan", cascade="all, delete-orphan")


class ModuleRecord(Base):
    __tablename__ = "modules"

    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, ForeignKey("scans.scan_id"), nullable=False)
    module_name = Column(String, nullable=False)
    status = Column(String, nullable=False)
    severity = Column(String, nullable=False)
    score = Column(Integer, nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    recommendations = Column(JSON, nullable=False, default=list)

    scan = relationship("ScanRecord", back_populates="modules")
