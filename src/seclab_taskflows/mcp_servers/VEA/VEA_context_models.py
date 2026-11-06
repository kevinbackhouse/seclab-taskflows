# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

from datetime import datetime, timezone
from sqlalchemy import String, Text, Integer, ForeignKey, Column, DateTime
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped, relationship
from typing import Optional


class Base(DeclarativeBase):
    pass


class VulnerableDeps(Base):
    __tablename__ = "vulnerable_deps"

    cve_id: Mapped[str]
    package_name: Mapped[str]
    vulnerable_version: Mapped[str]
    dependabot_pull_request: Mapped[str] = mapped_column(primary_key=True)
    created_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))
    modified_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))

    def __repr__(self):
        return (
            f"<VulnerableDeps(cve_id={self.cve_id}, package_name={self.package_name}, vulnerable_version={self.vulnerable_version}, dependabot_pull_request={self.dependabot_pull_request}, created_at={self.created_at}, modified_at={self.modified_at})>" 
        )

class CVEInfo(Base):
    __tablename__ = "cve_info"

    cve_id: Mapped[str] = mapped_column(primary_key=True)
    description: Mapped[str]
    source_location: Mapped[str]
    source_location_evidence: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))
    modified_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))


    def __repr__(self):
        return (
            f"<CVEInfo(cve_id={self.cve_id}, description={self.description}, source_location={self.source_location}, source_location_evidence={self.source_location_evidence}, created_at={self.created_at}, modified_at={self.modified_at})>" 
        )

class CandidateReachablePath(Base):
    __tablename__ = "candidate_reachable_path"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dependabot_pull_request: Mapped[str] = mapped_column(ForeignKey("vulnerable_deps.dependabot_pull_request"))
    path: Mapped[str]
    path_found_by: Mapped[str]
    created_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))
    modified_at: Mapped[datetime] = mapped_column(insert_default=datetime.now(timezone.utc))
    

    def __repr__(self):
        return (
            f"<CandidateReachablePath(id={self.id}, dependabot_pull_request={self.dependabot_pull_request}, path={self.path}, path_found_by={self.path_found_by}, created_at={self.created_at}, modified_at={self.modified_at})>" 
        )
