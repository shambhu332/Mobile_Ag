"""
Neo4j attack surface graph integration.
"""

import logging
from typing import Dict, Any, List, Optional
try:
    from neo4j import AsyncGraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

from mobileag.knowledge.schemas import (
    AppNode, ComponentNode, VulnerabilityNode, APIEndpointNode,
    HAS_COMPONENT, HAS_VULNERABILITY, CALLS_API
)
from mobileag.reporting.finding import Finding

logger = logging.getLogger(__name__)

class AttackGraph:
    """Manages the Neo4j attack surface graph."""
    
    def __init__(self, uri: str = "bolt://localhost:7687", user: str = "neo4j", password: str = "password"):
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        self._connected = False
        
        if NEO4J_AVAILABLE:
            try:
                self.driver = AsyncGraphDatabase.driver(uri, auth=(user, password))
            except Exception as e:
                logger.warning(f"Failed to initialize Neo4j driver for {uri}: {e}")
        else:
            logger.warning("neo4j driver not installed. Attack graph will operate in degraded mode.")

    async def verify_connection(self) -> bool:
        """Verify real network connectivity to the Neo4j instance."""
        if not self.driver:
            self._connected = False
            return False
        try:
            await self.driver.verify_connectivity()
            self._connected = True
            return True
        except Exception:
            self._connected = False
            return False

    async def initialize(self):
        """Creates constraints and indexes."""
        if not self._connected or not self.driver:
            return

        queries = [
            "CREATE CONSTRAINT app_scan_id IF NOT EXISTS FOR (a:App) REQUIRE a.scan_id IS UNIQUE",
            "CREATE CONSTRAINT comp_name IF NOT EXISTS FOR (c:Component) REQUIRE c.name IS UNIQUE",
            "CREATE CONSTRAINT vuln_id IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.finding_id IS UNIQUE"
        ]
        
        async with self.driver.session() as session:
            for query in queries:
                try:
                    await session.run(query)
                except Exception as e:
                    logger.warning(f"Failed to create constraint/index: {e}")

    async def add_app(self, scan_id: str, package_name: str, version: str = "", framework: str = "") -> None:
        """Creates an App node."""
        if not self._connected or not self.driver:
            return

        query = """
        MERGE (a:App {scan_id: $scan_id})
        SET a.package_name = $package_name, a.version = $version, a.framework = $framework
        """
        async with self.driver.session() as session:
            await session.run(query, scan_id=scan_id, package_name=package_name, version=version, framework=framework)

    async def add_component(self, scan_id: str, component_data: ComponentNode) -> None:
        """Creates a Component node and HAS_COMPONENT relation."""
        if not self._connected or not self.driver:
            return

        query = """
        MATCH (a:App {scan_id: $scan_id})
        MERGE (c:Component {name: $name})
        SET c.component_type = $component_type, c.exported = $exported, c.permission = $permission
        MERGE (a)-[:HAS_COMPONENT]->(c)
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                scan_id=scan_id,
                name=component_data.name,
                component_type=component_data.component_type,
                exported=component_data.exported,
                permission=component_data.permission
            )

    async def add_finding(self, scan_id: str, finding: Finding) -> None:
        """Creates a Vulnerability node and links to App."""
        if not self._connected or not self.driver:
            return

        query = """
        MATCH (a:App {scan_id: $scan_id})
        MERGE (v:Vulnerability {finding_id: $finding_id})
        SET v.title = $title, v.cwe = $cwe, v.severity = $severity, v.cvss = $cvss, v.confidence = $confidence
        MERGE (a)-[:HAS_VULNERABILITY]->(v)
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                scan_id=scan_id,
                finding_id=finding.id,
                title=finding.title,
                cwe=finding.cwe,
                severity=finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                cvss=finding.cvss_score,
                confidence=finding.confidence
            )

    async def add_api_endpoint(self, scan_id: str, endpoint_data: APIEndpointNode) -> None:
        """Creates an API node and links to App."""
        if not self._connected or not self.driver:
            return
            
        query = """
        MATCH (a:App {scan_id: $scan_id})
        MERGE (e:APIEndpoint {url: $url})
        SET e.method = $method, e.requires_auth = $requires_auth
        MERGE (a)-[:CALLS_API]->(e)
        """
        async with self.driver.session() as session:
            await session.run(
                query,
                scan_id=scan_id,
                url=endpoint_data.url,
                method=endpoint_data.method,
                requires_auth=endpoint_data.requires_auth
            )

    async def find_attack_chains(self, scan_id: str) -> List[Dict[str, Any]]:
        """Cypher query to find multi-step attack paths."""
        if not self._connected or not self.driver:
            return []

        query = """
        MATCH (a:App {scan_id: $scan_id})-[:HAS_COMPONENT]->(c:Component {exported: true})
        MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        RETURN c.name AS component, c.component_type AS type, v.title AS vulnerability, v.severity AS severity
        """
        chains = []
        async with self.driver.session() as session:
            result = await session.run(query, scan_id=scan_id)
            async for record in result:
                chains.append({
                    "component": record["component"],
                    "type": record["type"],
                    "vulnerability": record["vulnerability"],
                    "severity": record["severity"]
                })
        return chains

    async def get_attack_surface_summary(self, scan_id: str) -> Dict[str, Any]:
        """Summary stats of the attack surface."""
        if not self._connected or not self.driver:
            return {"status": "neo4j not available"}

        query = """
        MATCH (a:App {scan_id: $scan_id})
        OPTIONAL MATCH (a)-[:HAS_COMPONENT]->(c:Component)
        OPTIONAL MATCH (a)-[:HAS_VULNERABILITY]->(v:Vulnerability)
        OPTIONAL MATCH (a)-[:CALLS_API]->(e:APIEndpoint)
        RETURN 
            COUNT(DISTINCT c) AS components_count,
            COUNT(DISTINCT v) AS vulns_count,
            COUNT(DISTINCT e) AS apis_count
        """
        async with self.driver.session() as session:
            result = await session.run(query, scan_id=scan_id)
            record = await result.single()
            if record:
                return {
                    "components_count": record["components_count"],
                    "vulns_count": record["vulns_count"],
                    "apis_count": record["apis_count"]
                }
        return {}

    async def export_visjs_graph(self, scan_id: str) -> Optional[Dict[str, List[Dict[str, Any]]]]:
        """Query Neo4j and return Vis.js compatible nodes and edges."""
        if not self._connected or not self.driver:
            return None

        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: set = set()

        query = """
        MATCH (a:App {scan_id: $scan_id})
        OPTIONAL MATCH (a)-[r]->(target)
        RETURN a, type(r) AS rel_type, target, labels(target) AS target_labels
        """

        color_map = {
            "App": "#00F0FF",
            "Component": "#00E599",
            "Vulnerability": "#FF0055",
            "APIEndpoint": "#FF8800",
            "Secret": "#F59E0B"
        }

        try:
            async with self.driver.session() as session:
                result = await session.run(query, scan_id=scan_id)
                async for record in result:
                    a = record["a"]
                    if a and a.get("scan_id") not in seen_nodes:
                        seen_nodes.add(a.get("scan_id"))
                        nodes.append({
                            "id": a.get("scan_id"),
                            "label": f"{a.get('package_name', 'App')}\n(v{a.get('version', '1.0')})",
                            "group": "app",
                            "shape": "dot",
                            "size": 32,
                            "color": color_map["App"]
                        })

                    target = record["target"]
                    rel_type = record["rel_type"]
                    labels = record["target_labels"] or []
                    primary_label = labels[0] if labels else "Component"

                    if target:
                        target_id = target.get("finding_id") or target.get("name") or target.get("url") or str(id(target))
                        if target_id not in seen_nodes:
                            seen_nodes.add(target_id)
                            label_txt = target.get("name") or target.get("title") or target.get("url") or "Node"
                            nodes.append({
                                "id": target_id,
                                "label": label_txt[:35],
                                "group": primary_label.lower(),
                                "shape": "square" if primary_label == "Vulnerability" else "dot",
                                "size": 24 if primary_label == "Vulnerability" else 20,
                                "color": color_map.get(primary_label, "#94A3B8")
                            })

                        if a and rel_type:
                            edges.append({
                                "from": a.get("scan_id"),
                                "to": target_id,
                                "label": rel_type.replace("HAS_", "").replace("CALLS_", "").lower()
                            })

            return {"nodes": nodes, "edges": edges} if nodes else None
        except Exception as e:
            logger.warning(f"Failed to query Neo4j for Vis.js export: {e}")
            return None

    async def close(self) -> None:
        """Close the Neo4j driver."""
        if self.driver:
            await self.driver.close()
            self._connected = False
