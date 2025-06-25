"""
Business Impact Analyzer Module

Analyzes the potential business impact of network configuration changes
by mapping dependencies and calculating risk scores.
"""

import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import networkx as nx
import pandas as pd
from enum import Enum

logger = logging.getLogger(__name__)


class ImpactLevel(Enum):
    """Impact severity levels"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ServiceStatus(Enum):
    """Service operational status"""
    OPERATIONAL = "operational"
    DEGRADED = "degraded"
    AT_RISK = "at_risk"
    DOWN = "down"


@dataclass
class BusinessService:
    """Represents a business service"""
    name: str
    description: str
    criticality: ImpactLevel
    owner: str
    sla_target: float  # Uptime percentage
    revenue_per_hour: float = 0.0
    users_affected: int = 0
    dependencies: List[str] = field(default_factory=list)
    network_dependencies: List[str] = field(default_factory=list)


@dataclass
class NetworkPath:
    """Represents a network path between services"""
    source: str
    destination: str
    devices: List[str]
    protocols: List[str]
    bandwidth_required: float = 0.0
    latency_threshold: float = 100.0  # milliseconds


@dataclass
class ImpactAssessment:
    """Results of business impact analysis"""
    change_id: str
    timestamp: datetime
    affected_devices: List[str]
    affected_services: List[Tuple[str, ImpactLevel]]
    total_revenue_risk: float
    total_users_affected: int
    risk_score: float
    recommendations: List[str]
    mitigation_steps: List[str]


class BusinessImpactAnalyzer:
    """
    Analyzes business impact of network changes by understanding
    service dependencies and calculating risk
    """
    
    def __init__(self):
        """Initialize the impact analyzer"""
        self.services: Dict[str, BusinessService] = {}
        self.network_paths: List[NetworkPath] = []
        self.dependency_graph = nx.DiGraph()
        self.device_to_services: Dict[str, Set[str]] = {}
        
    def add_service(self, service: BusinessService) -> None:
        """Add a business service to the analyzer"""
        self.services[service.name] = service
        self.dependency_graph.add_node(service.name, **service.__dict__)
        
        # Add edges for service dependencies
        for dep in service.dependencies:
            self.dependency_graph.add_edge(service.name, dep)
            
        # Map network device dependencies
        for device in service.network_dependencies:
            if device not in self.device_to_services:
                self.device_to_services[device] = set()
            self.device_to_services[device].add(service.name)
            
        logger.info(f"Added business service: {service.name}")
        
    def add_network_path(self, path: NetworkPath) -> None:
        """Add a network path definition"""
        self.network_paths.append(path)
        
        # Update device to service mappings
        for device in path.devices:
            if device not in self.device_to_services:
                self.device_to_services[device] = set()
            self.device_to_services[device].add(path.source)
            self.device_to_services[device].add(path.destination)
            
    def analyze_device_impact(self, devices: List[str], 
                            change_type: str = "configuration",
                            downtime_minutes: int = 0) -> ImpactAssessment:
        """
        Analyze the business impact of changes to specific devices
        
        Args:
            devices: List of device hostnames
            change_type: Type of change (configuration, reboot, upgrade)
            downtime_minutes: Expected downtime in minutes
            
        Returns:
            ImpactAssessment with detailed analysis
        """
        affected_services = set()
        
        # Find all services affected by the devices
        for device in devices:
            if device in self.device_to_services:
                affected_services.update(self.device_to_services[device])
                
        # Calculate cascade effects through dependency graph
        all_affected = set()
        for service in affected_services:
            all_affected.add(service)
            # Find all services that depend on this service
            dependents = nx.descendants(self.dependency_graph, service)
            all_affected.update(dependents)
            
        # Calculate business impact metrics
        total_revenue_risk = 0.0
        total_users = 0
        service_impacts = []
        
        for service_name in all_affected:
            if service_name in self.services:
                service = self.services[service_name]
                
                # Calculate revenue impact
                if downtime_minutes > 0:
                    revenue_impact = (service.revenue_per_hour / 60) * downtime_minutes
                else:
                    # For config changes without downtime, use risk factor
                    revenue_impact = service.revenue_per_hour * 0.01  # 1% risk
                    
                total_revenue_risk += revenue_impact
                total_users += service.users_affected
                
                # Determine impact level based on service criticality and change type
                if change_type == "reboot" or downtime_minutes > 0:
                    impact_level = service.criticality
                else:
                    # Configuration changes have lower impact
                    impact_level = ImpactLevel(max(0, service.criticality.value - 1))
                    
                service_impacts.append((service_name, impact_level))
                
        # Calculate overall risk score (0-100)
        risk_score = self._calculate_risk_score(
            len(affected_services),
            len(all_affected),
            total_revenue_risk,
            change_type,
            max([impact[1].value for impact in service_impacts] + [0])
        )
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            devices, service_impacts, change_type, risk_score
        )
        
        # Generate mitigation steps
        mitigation_steps = self._generate_mitigation_steps(
            devices, service_impacts, change_type
        )
        
        assessment = ImpactAssessment(
            change_id=f"CHG-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            timestamp=datetime.now(),
            affected_devices=devices,
            affected_services=service_impacts,
            total_revenue_risk=total_revenue_risk,
            total_users_affected=total_users,
            risk_score=risk_score,
            recommendations=recommendations,
            mitigation_steps=mitigation_steps
        )
        
        logger.info(f"Impact analysis completed: Risk Score = {risk_score:.1f}")
        return assessment
        
    def _calculate_risk_score(self, direct_services: int, total_services: int,
                            revenue_risk: float, change_type: str,
                            max_criticality: int) -> float:
        """Calculate risk score from 0-100"""
        # Base score components
        service_score = (total_services / len(self.services)) * 25 if self.services else 0
        
        # Revenue risk score (normalized to 0-25)
        revenue_score = min(25, (revenue_risk / 10000) * 25)  # $10k = max score
        
        # Criticality score (0-25)
        criticality_score = (max_criticality / 4) * 25
        
        # Change type score (0-25)
        change_scores = {
            "configuration": 10,
            "upgrade": 15,
            "reboot": 20,
            "hardware": 25
        }
        type_score = change_scores.get(change_type, 15)
        
        total_score = service_score + revenue_score + criticality_score + type_score
        return min(100, total_score)
        
    def _generate_recommendations(self, devices: List[str], 
                                service_impacts: List[Tuple[str, ImpactLevel]],
                                change_type: str, risk_score: float) -> List[str]:
        """Generate recommendations based on impact analysis"""
        recommendations = []
        
        if risk_score > 75:
            recommendations.append("HIGH RISK: Consider scheduling during maintenance window")
            recommendations.append("Notify all service owners before proceeding")
            recommendations.append("Ensure rollback plan is tested and ready")
            
        elif risk_score > 50:
            recommendations.append("MEDIUM RISK: Schedule during low-traffic period")
            recommendations.append("Have support staff on standby")
            
        if any(impact[1] == ImpactLevel.CRITICAL for impact in service_impacts):
            recommendations.append("Critical services affected - executive approval required")
            
        if len(devices) > 5:
            recommendations.append("Consider phased rollout due to number of devices affected")
            
        # Check for redundancy
        if self._check_redundancy(devices):
            recommendations.append("Redundant paths available - consider rolling changes")
        else:
            recommendations.append("No redundancy detected - plan for service interruption")
            
        return recommendations
        
    def _generate_mitigation_steps(self, devices: List[str],
                                 service_impacts: List[Tuple[str, ImpactLevel]],
                                 change_type: str) -> List[str]:
        """Generate specific mitigation steps"""
        steps = []
        
        steps.append("1. Create configuration backup for all affected devices")
        steps.append("2. Verify rollback procedures are documented and tested")
        
        if change_type in ["upgrade", "reboot"]:
            steps.append("3. Notify users of planned maintenance window")
            steps.append("4. Prepare failover to backup systems if available")
            
        steps.append(f"{len(steps)+1}. Monitor service health dashboards during change")
        steps.append(f"{len(steps)+1}. Have escalation contacts ready")
        
        if any(impact[1].value >= ImpactLevel.HIGH.value for impact in service_impacts):
            steps.append(f"{len(steps)+1}. Schedule bridge call with stakeholders")
            steps.append(f"{len(steps)+1}. Prepare status updates for executive team")
            
        return steps
        
    def _check_redundancy(self, devices: List[str]) -> bool:
        """Check if redundant paths exist for affected devices"""
        for path in self.network_paths:
            affected_in_path = [d for d in devices if d in path.devices]
            if affected_in_path and len(affected_in_path) < len(path.devices):
                # Some devices in path are not affected, redundancy exists
                return True
        return False
        
    def generate_impact_report(self, assessment: ImpactAssessment) -> str:
        """Generate a formatted impact report"""
        report = f"""
BUSINESS IMPACT ANALYSIS REPORT
==============================
Change ID: {assessment.change_id}
Generated: {assessment.timestamp.strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
-----------------
Risk Score: {assessment.risk_score:.1f}/100 {'⚠️ HIGH RISK' if assessment.risk_score > 75 else ''}
Revenue at Risk: ${assessment.total_revenue_risk:,.2f}
Users Affected: {assessment.total_users_affected:,}
Devices: {', '.join(assessment.affected_devices)}

AFFECTED SERVICES
-----------------
"""
        for service, impact in assessment.affected_services:
            impact_icon = ['✓', '⚡', '⚠️', '🔥', '💀'][impact.value]
            report += f"{impact_icon} {service} - {impact.name}\n"
            
        report += f"""
RECOMMENDATIONS
---------------
"""
        for i, rec in enumerate(assessment.recommendations, 1):
            report += f"{i}. {rec}\n"
            
        report += f"""
MITIGATION STEPS
----------------
"""
        for step in assessment.mitigation_steps:
            report += f"{step}\n"
            
        return report
        
    def export_dependency_graph(self, filename: str = "service_dependencies.png") -> None:
        """Export the service dependency graph as an image"""
        import matplotlib.pyplot as plt
        
        plt.figure(figsize=(12, 8))
        pos = nx.spring_layout(self.dependency_graph)
        
        # Color nodes by criticality
        colors = []
        for node in self.dependency_graph.nodes():
            if node in self.services:
                criticality = self.services[node].criticality.value
                colors.append(['green', 'yellow', 'orange', 'red', 'darkred'][criticality])
            else:
                colors.append('gray')
                
        nx.draw(self.dependency_graph, pos, node_color=colors, 
                with_labels=True, node_size=3000, font_size=10,
                font_weight='bold', arrows=True)
                
        plt.title("Business Service Dependencies")
        plt.savefig(filename)
        plt.close()
        logger.info(f"Dependency graph exported to {filename}")
