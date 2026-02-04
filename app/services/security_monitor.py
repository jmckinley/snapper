"""Security monitoring and research integration service."""

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.agents import Agent
from app.models.audit_logs import AuditLog, AuditSeverity, PolicyViolation
from app.models.rules import Rule, RuleAction, RuleType
from app.models.security_issues import (
    IssueSeverity,
    IssueStatus,
    MaliciousSkill,
    SecurityIssue,
    SecurityRecommendation,
)
from app.redis_client import RedisClient

logger = logging.getLogger(__name__)


class SecurityMonitor:
    """
    Security monitoring service.

    Provides:
    - Security score calculation
    - Threat intelligence integration
    - Recommendation generation
    - Compliance reporting
    """

    # Score weights for different factors
    SCORE_WEIGHTS = {
        "rule_coverage": 25,
        "cve_mitigation": 20,
        "skill_protection": 20,
        "credential_protection": 15,
        "rate_limiting": 10,
        "audit_compliance": 10,
    }

    def __init__(self, db: AsyncSession, redis: RedisClient):
        self.db = db
        self.redis = redis

    async def calculate_security_score(
        self,
        agent_id: Optional[UUID] = None,
    ) -> Dict[str, Any]:
        """
        Calculate security score for an agent or globally.

        Score ranges from 0-100 with letter grades:
        A+ (95-100), A (90-94), B+ (85-89), B (80-84),
        C+ (75-79), C (70-74), D (60-69), F (<60)
        """
        breakdown = {}
        positive_factors = []
        negative_factors = []

        # 1. Rule Coverage (25 points)
        rule_score = await self._calculate_rule_coverage_score(agent_id)
        breakdown["rule_coverage"] = rule_score
        if rule_score >= 20:
            positive_factors.append("Strong rule coverage")
        elif rule_score < 10:
            negative_factors.append("Insufficient security rules")

        # 2. CVE Mitigation (20 points)
        cve_score = await self._calculate_cve_mitigation_score(agent_id)
        breakdown["cve_mitigation"] = cve_score
        if cve_score >= 18:
            positive_factors.append("All critical CVEs mitigated")
        elif cve_score < 10:
            negative_factors.append("Unmitigated critical vulnerabilities")

        # 3. Skill Protection (20 points)
        skill_score = await self._calculate_skill_protection_score(agent_id)
        breakdown["skill_protection"] = skill_score
        if skill_score >= 18:
            positive_factors.append("ClawHub skill protection enabled")
        elif skill_score < 10:
            negative_factors.append("Malicious skills not blocked")

        # 4. Credential Protection (15 points)
        cred_score = await self._calculate_credential_protection_score(agent_id)
        breakdown["credential_protection"] = cred_score
        if cred_score >= 13:
            positive_factors.append("Credential exposure protected")
        elif cred_score < 8:
            negative_factors.append("Credentials may be exposed")

        # 5. Rate Limiting (10 points)
        rate_score = await self._calculate_rate_limit_score(agent_id)
        breakdown["rate_limiting"] = rate_score
        if rate_score >= 8:
            positive_factors.append("Rate limiting configured")
        elif rate_score < 5:
            negative_factors.append("No rate limiting")

        # 6. Audit Compliance (10 points)
        audit_score = await self._calculate_audit_compliance_score(agent_id)
        breakdown["audit_compliance"] = audit_score
        if audit_score >= 8:
            positive_factors.append("Comprehensive audit logging")
        elif audit_score < 5:
            negative_factors.append("Insufficient audit logging")

        # Calculate total score
        total_score = sum(breakdown.values())
        grade = self._score_to_grade(total_score)

        # Get previous score for comparison
        previous_score = await self._get_previous_score(agent_id)
        score_change = total_score - previous_score if previous_score else 0

        # Store current score
        await self._store_score(agent_id, total_score)

        return {
            "agent_id": agent_id,
            "score": total_score,
            "grade": grade,
            "calculated_at": datetime.utcnow(),
            "breakdown": breakdown,
            "positive_factors": positive_factors,
            "negative_factors": negative_factors,
            "previous_score": previous_score,
            "score_change": score_change,
            "improvement_suggestions": await self._get_improvement_suggestions(
                agent_id, breakdown
            ),
        }

    async def _calculate_rule_coverage_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on rule coverage."""
        max_score = self.SCORE_WEIGHTS["rule_coverage"]

        # Query rules
        stmt = select(Rule).where(
            Rule.is_active == True,
            Rule.is_deleted == False,
        )
        if agent_id:
            stmt = stmt.where(
                (Rule.agent_id == agent_id) | (Rule.agent_id == None)
            )

        result = await self.db.execute(stmt)
        rules = list(result.scalars().all())

        if not rules:
            return 0

        # Check coverage of important rule types
        covered_types = {r.rule_type for r in rules}
        important_types = {
            RuleType.ORIGIN_VALIDATION,
            RuleType.SKILL_DENYLIST,
            RuleType.CREDENTIAL_PROTECTION,
            RuleType.LOCALHOST_RESTRICTION,
            RuleType.RATE_LIMIT,
        }

        coverage = len(covered_types & important_types) / len(important_types)
        return int(coverage * max_score)

    async def _calculate_cve_mitigation_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on CVE mitigation."""
        max_score = self.SCORE_WEIGHTS["cve_mitigation"]

        # Query active critical/high CVEs
        stmt = select(SecurityIssue).where(
            SecurityIssue.status == IssueStatus.ACTIVE,
            SecurityIssue.severity.in_([IssueSeverity.CRITICAL, IssueSeverity.HIGH]),
        )
        result = await self.db.execute(stmt)
        active_issues = list(result.scalars().all())

        if not active_issues:
            return max_score  # No active issues = full score

        # Check how many have mitigation rules
        mitigated = sum(1 for issue in active_issues if issue.mitigation_rules)
        mitigation_rate = mitigated / len(active_issues)

        return int(mitigation_rate * max_score)

    async def _calculate_skill_protection_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on skill protection."""
        max_score = self.SCORE_WEIGHTS["skill_protection"]

        # Check for skill denylist rules
        stmt = select(Rule).where(
            Rule.is_active == True,
            Rule.is_deleted == False,
            Rule.rule_type == RuleType.SKILL_DENYLIST,
        )
        if agent_id:
            stmt = stmt.where(
                (Rule.agent_id == agent_id) | (Rule.agent_id == None)
            )

        result = await self.db.execute(stmt)
        skill_rules = list(result.scalars().all())

        if not skill_rules:
            return 0

        # Check if auto-block is enabled
        has_auto_block = any(
            r.parameters.get("auto_block_flagged", False)
            for r in skill_rules
        )

        if has_auto_block:
            return max_score

        # Partial score for having rules without auto-block
        return max_score // 2

    async def _calculate_credential_protection_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on credential protection."""
        max_score = self.SCORE_WEIGHTS["credential_protection"]

        # Check for credential protection rules
        stmt = select(Rule).where(
            Rule.is_active == True,
            Rule.is_deleted == False,
            Rule.rule_type == RuleType.CREDENTIAL_PROTECTION,
        )
        if agent_id:
            stmt = stmt.where(
                (Rule.agent_id == agent_id) | (Rule.agent_id == None)
            )

        result = await self.db.execute(stmt)
        cred_rules = list(result.scalars().all())

        if not cred_rules:
            return 0

        # Check for comprehensive protection
        patterns_covered = set()
        for rule in cred_rules:
            patterns_covered.update(rule.parameters.get("protected_patterns", []))

        essential_patterns = {".env", ".pem", ".key", "credentials"}
        coverage = len(patterns_covered & essential_patterns) / len(essential_patterns)

        return int(coverage * max_score)

    async def _calculate_rate_limit_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on rate limiting."""
        max_score = self.SCORE_WEIGHTS["rate_limiting"]

        # Check for rate limit rules
        stmt = select(Rule).where(
            Rule.is_active == True,
            Rule.is_deleted == False,
            Rule.rule_type == RuleType.RATE_LIMIT,
        )
        if agent_id:
            stmt = stmt.where(
                (Rule.agent_id == agent_id) | (Rule.agent_id == None)
            )

        result = await self.db.execute(stmt)
        rate_rules = list(result.scalars().all())

        if rate_rules:
            return max_score

        return 0

    async def _calculate_audit_compliance_score(
        self, agent_id: Optional[UUID]
    ) -> int:
        """Calculate score based on audit logging compliance."""
        max_score = self.SCORE_WEIGHTS["audit_compliance"]

        # Check recent audit log entries
        cutoff = datetime.utcnow() - timedelta(days=7)
        stmt = select(func.count(AuditLog.id)).where(
            AuditLog.created_at >= cutoff,
        )
        if agent_id:
            stmt = stmt.where(AuditLog.agent_id == agent_id)

        result = await self.db.execute(stmt)
        log_count = result.scalar() or 0

        # Having audit logs is good
        if log_count > 0:
            return max_score

        return 0

    def _score_to_grade(self, score: int) -> str:
        """Convert numeric score to letter grade."""
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    async def _get_previous_score(
        self, agent_id: Optional[UUID]
    ) -> Optional[int]:
        """Get previous security score from cache."""
        key = f"security_score:{agent_id or 'global'}:previous"
        score = await self.redis.get(key)
        return int(score) if score else None

    async def _store_score(
        self, agent_id: Optional[UUID], score: int
    ) -> None:
        """Store current score and update previous."""
        key = f"security_score:{agent_id or 'global'}"
        previous_key = f"{key}:previous"

        # Get current to become previous
        current = await self.redis.get(key)
        if current:
            await self.redis.set(previous_key, current, expire=86400 * 7)

        # Store new current
        await self.redis.set(key, str(score), expire=3600)

    async def _get_improvement_suggestions(
        self,
        agent_id: Optional[UUID],
        breakdown: Dict[str, int],
    ) -> List[Dict[str, Any]]:
        """Generate suggestions for improving security score."""
        suggestions = []

        max_weights = self.SCORE_WEIGHTS

        for factor, score in breakdown.items():
            max_score = max_weights.get(factor, 0)
            if score < max_score * 0.7:  # Less than 70% of possible points
                suggestion = self._get_suggestion_for_factor(factor)
                if suggestion:
                    suggestions.append({
                        "factor": factor,
                        "current_score": score,
                        "max_score": max_score,
                        "potential_gain": max_score - score,
                        **suggestion,
                    })

        # Sort by potential gain
        suggestions.sort(key=lambda s: s["potential_gain"], reverse=True)
        return suggestions[:5]  # Top 5 suggestions

    def _get_suggestion_for_factor(self, factor: str) -> Optional[Dict[str, Any]]:
        """Get improvement suggestion for a specific factor."""
        suggestions = {
            "rule_coverage": {
                "title": "Improve Rule Coverage",
                "description": "Add rules for origin validation, credential protection, and skill blocking",
                "action": "Add security rules from recommended templates",
            },
            "cve_mitigation": {
                "title": "Mitigate Active CVEs",
                "description": "Apply mitigation rules for unaddressed vulnerabilities",
                "action": "Review and apply CVE mitigation recommendations",
            },
            "skill_protection": {
                "title": "Enable Skill Protection",
                "description": "Block malicious ClawHub skills automatically",
                "action": "Enable skill denylist with auto-block",
            },
            "credential_protection": {
                "title": "Protect Credentials",
                "description": "Prevent access to sensitive credential files",
                "action": "Add credential protection rules",
            },
            "rate_limiting": {
                "title": "Configure Rate Limiting",
                "description": "Prevent abuse with request rate limits",
                "action": "Add rate limiting rules",
            },
            "audit_compliance": {
                "title": "Ensure Audit Logging",
                "description": "Comprehensive logging for security compliance",
                "action": "Review audit log configuration",
            },
        }
        return suggestions.get(factor)

    async def get_active_threats(
        self,
        agent_id: Optional[UUID] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get active threats for dashboard display."""
        threats = []

        # Get active CVEs
        stmt = select(SecurityIssue).where(
            SecurityIssue.status == IssueStatus.ACTIVE,
        ).order_by(
            SecurityIssue.severity,
            SecurityIssue.published_at.desc(),
        ).limit(limit // 2)

        result = await self.db.execute(stmt)
        cves = list(result.scalars().all())

        for cve in cves:
            threats.append({
                "type": "cve",
                "id": str(cve.id),
                "title": cve.cve_id or cve.title,
                "severity": cve.severity,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "is_mitigated": bool(cve.mitigation_rules),
            })

        # Get recent malicious skills
        stmt = select(MaliciousSkill).where(
            MaliciousSkill.is_blocked == True,
        ).order_by(
            MaliciousSkill.last_seen_at.desc(),
        ).limit(limit // 2)

        result = await self.db.execute(stmt)
        skills = list(result.scalars().all())

        for skill in skills:
            threats.append({
                "type": "malicious_skill",
                "id": str(skill.id),
                "title": f"Malicious skill: {skill.skill_name}",
                "severity": skill.severity,
                "description": skill.analysis_notes or f"Detected {skill.threat_type} threat",
                "is_blocked": skill.is_blocked,
            })

        return threats

    async def get_recent_violations(
        self,
        agent_id: Optional[UUID] = None,
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get recent policy violations."""
        stmt = select(PolicyViolation).where(
            PolicyViolation.is_resolved == False,
        )
        if agent_id:
            stmt = stmt.where(PolicyViolation.agent_id == agent_id)

        stmt = stmt.order_by(
            PolicyViolation.created_at.desc(),
        ).limit(limit)

        result = await self.db.execute(stmt)
        violations = list(result.scalars().all())

        return [
            {
                "id": str(v.id),
                "type": v.violation_type,
                "severity": v.severity,
                "description": v.description,
                "created_at": v.created_at,
            }
            for v in violations
        ]
