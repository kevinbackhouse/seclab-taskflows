# SPDX-FileCopyrightText: GitHub, Inc.
# SPDX-License-Identifier: MIT

import logging
from fastmcp import FastMCP
from pydantic import Field
import httpx
import json
import os
import yaml
from sqlalchemy.orm import DeclarativeBase, mapped_column, Mapped
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from pathlib import Path
from datetime import datetime, timezone
from seclab_taskflow_agent.path_utils import mcp_data_dir, log_file_name
from .VEA_context_models import CVEInfo, VulnerableDeps, CandidateReachablePath, Base

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filename=log_file_name("mcp_VEA_context.log"),
    filemode="a",
)

MEMORY = mcp_data_dir("seclab-taskflows", "VEA", "VEA_CONTEXT_DIR")

def vulnerable_deps_to_dict(result):
    return {
        "cve_id": result.cve_id,
        "package_name": result.package_name,
        "vulnerable_version": result.vulnerable_version,
    }

def candidate_reachable_path_to_dict(result):
    return {
        "path": result.path,
        "path_found_by": result.path_found_by,
    }

class VEAContextBackend:
    def __init__(self, memcache_state_dir: str):
        self.memcache_state_dir = memcache_state_dir
        if not Path(self.memcache_state_dir).exists():
            db_dir = "sqlite://"
        else:
            db_dir = f"sqlite:///{self.memcache_state_dir}/VEA_context.db"
        self.engine = create_engine(db_dir, echo=False)
        Base.metadata.create_all(
            self.engine,
            tables=[
                VulnerableDeps.__table__,
                CVEInfo.__table__,
                CandidateReachablePath.__table__,
            ],
        )

    def store_new_vulnerable_dep(self, cve_id, package_name, vulnerable_version, dependabot_pull_request):
        with Session(self.engine) as session:
            stmt = sqlite_insert(VulnerableDeps).values(
                cve_id=cve_id,
                package_name=package_name,
                vulnerable_version=vulnerable_version,
                dependabot_pull_request=dependabot_pull_request,
            )
            upsert_stmt = stmt.on_conflict_do_update(
                index_elements=[VulnerableDeps.dependabot_pull_request],
                set_={
                    "cve_id": cve_id,
                    "package_name": package_name,
                    "vulnerable_version": vulnerable_version,
                    "modified_at": datetime.now(timezone.utc),
                },
            )
            session.execute(upsert_stmt)
            session.commit()
        return f"Updated or added vulnerable dependency for {package_name} with CVE {cve_id}."


    def get_vulnerable_deps(self, dependabot_pull_request: str):
        with Session(self.engine) as session:
            existing = session.query(VulnerableDeps).filter(VulnerableDeps.dependabot_pull_request == dependabot_pull_request).all()
        logging.debug(f"Retrieved vulnerable dependencies for {dependabot_pull_request}: {existing}")
        return [vulnerable_deps_to_dict(dep) for dep in existing]

    def store_CVE_info(self, cve_id, description, source_location, source_location_evidence):
        with Session(self.engine) as session:
            stmt = sqlite_insert(CVEInfo).values(
                cve_id=cve_id,
                description=description,
                source_location=source_location,
                source_location_evidence=source_location_evidence,
            )
            upsert_stmt = stmt.on_conflict_do_update(
                index_elements=[CVEInfo.cve_id],
                set_={
                    "description": description,
                    "source_location": source_location,
                    "source_location_evidence": source_location_evidence,
                    "modified_at": datetime.now(timezone.utc),
                },
            )
            session.execute(upsert_stmt)
            session.commit()
        logging.debug(f"Stored CVE info for {cve_id}: description={description}, source_location={source_location}, source_location_evidence={source_location_evidence}")
        return f"Updated or added CVE info for CVE {cve_id}."

    def get_CVE_info(self, cve_id):
        with Session(self.engine) as session:
            info = session.query(CVEInfo).filter(CVEInfo.cve_id == cve_id).first()
        if info:
            return {
                "cve_id": info.cve_id,
                "description": info.description,
                "source_location": info.source_location,
                "source_location_evidence": info.source_location_evidence,
            }
        else:
            return None

    def store_candidate_reachable_path(self, dependabot_pull_request, path, path_found_by):
        with Session(self.engine) as session:
            new_path = CandidateReachablePath(
                dependabot_pull_request=dependabot_pull_request,
                path=path,
                path_found_by=path_found_by,
            )
            session.add(new_path)
            session.commit()
        return f"Added candidate reachable path for pull request {dependabot_pull_request}."

    def get_candidate_reachable_paths(self, dependabot_pull_request: str):
        with Session(self.engine) as session:
            paths = session.query(CandidateReachablePath).filter(CandidateReachablePath.dependabot_pull_request == dependabot_pull_request).all()
        logging.debug(f"Retrieved candidate reachable paths for {dependabot_pull_request}: {paths}")
        return [candidate_reachable_path_to_dict(path) for path in paths]

mcp = FastMCP("VEAContext")

backend = VEAContextBackend(MEMORY)


@mcp.tool()
def store_new_vulnerable_dep(
    cve_id: str = Field(description="The CVE ID of the vulnerability"),
    package_name: str = Field(description="The name of the vulnerable package"),
    vulnerable_version: str = Field(description="The version of the package that is vulnerable"),
    dependabot_pull_request: str = Field(description="The URL of the dependabot pull request"),
):
    """
    Stores a new vulnerable dependency in the database. 
    """
    return backend.store_new_vulnerable_dep(cve_id, package_name, vulnerable_version, dependabot_pull_request)


@mcp.tool()
def get_vulnerable_deps(dependabot_pull_request: str = Field(description="The URL of the dependabot pull request")):
    """
    Get all vulnerable dependencies mentioned in the pull request.
    """
    return json.dumps(backend.get_vulnerable_deps(dependabot_pull_request))



@mcp.tool()
def store_CVE_info(
    cve_id: str = Field(description="The CVE ID of the vulnerability"),
    description: str = Field(description="The description of the CVE"),
    source_location: str = Field(description="The source location of the vulnerability"),
    source_location_evidence: str = Field(description="The evidence for the source location of the vulnerability"),
):
    """
    Stores additional information about a CVE in the database. 
    """
    return backend.store_CVE_info(cve_id, description, source_location, source_location_evidence)


@mcp.tool()
def get_CVE_info(
    cve_id: str = Field(description="The CVE ID of the vulnerability")
):
    """
    Get information about a specific CVE from the database.
    """
    return backend.get_CVE_info(cve_id)

@mcp.tool()
def store_candidate_reachable_path(
    dependabot_pull_request: str = Field(description="The URL of the dependabot pull request"),
    path: str = Field(description="A possible reachable path for the vulnerability"),
    path_found_by: str = Field(description="Explanation of how the path was found"),
):
    """
    Stores a new candidate reachable path in the database.
    """
    return backend.store_candidate_reachable_path(dependabot_pull_request, path, path_found_by)

@mcp.tool()
def get_candidate_reachable_paths(dependabot_pull_request: str = Field(description="The URL of the dependabot pull request")):
    """
    Get all candidate reachable paths for a specific pull request.
    """
    return json.dumps(backend.get_candidate_reachable_paths(dependabot_pull_request))

if __name__ == "__main__":
    mcp.run(show_banner=False)
