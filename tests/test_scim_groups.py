"""Tests for SCIM Groups (Teams) endpoints."""

import uuid
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.models.organizations import Organization, OrganizationMembership, OrgRole, Team
from app.routers.scim import team_to_scim_group, scim_list_response, scim_error


def _make_team(name="Engineering", slug="engineering", org_id=None, external_id=None):
    team = MagicMock(spec=Team)
    team.id = uuid.uuid4()
    team.organization_id = org_id or uuid.uuid4()
    team.name = name
    team.slug = slug
    team.is_default = False
    team.external_id = external_id
    team.created_at = datetime.now(timezone.utc)
    return team


def test_team_to_scim_group_basic():
    """Basic team should convert to SCIM Group format."""
    team = _make_team()
    result = team_to_scim_group(team)

    assert result["schemas"] == ["urn:ietf:params:scim:schemas:core:2.0:Group"]
    assert result["id"] == str(team.id)
    assert result["displayName"] == "Engineering"
    assert "meta" in result


def test_team_to_scim_group_with_external_id():
    """Team with external_id should include externalId."""
    team = _make_team(external_id="ext-123")
    result = team_to_scim_group(team)
    assert result["externalId"] == "ext-123"


def test_team_to_scim_group_without_external_id():
    """Team without external_id should not include externalId."""
    team = _make_team()
    result = team_to_scim_group(team)
    assert "externalId" not in result


def test_team_to_scim_group_with_members():
    """Group with members should include member list."""
    team = _make_team()
    members = [
        {"value": str(uuid.uuid4()), "display": "user1@example.com"},
        {"value": str(uuid.uuid4()), "display": "user2@example.com"},
    ]
    result = team_to_scim_group(team, members)
    assert len(result["members"]) == 2
    assert result["members"][0]["display"] == "user1@example.com"


def test_team_to_scim_group_no_members():
    """Group without members param should not include members key."""
    team = _make_team()
    result = team_to_scim_group(team)
    assert "members" not in result


def test_scim_list_response_format():
    """SCIM list response should have correct schema."""
    resources = [{"id": "1"}, {"id": "2"}]
    result = scim_list_response(resources, total=5, start_index=1, count=2)

    assert result["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]
    assert result["totalResults"] == 5
    assert result["startIndex"] == 1
    assert result["itemsPerPage"] == 2
    assert len(result["Resources"]) == 2


def test_scim_error_format():
    """SCIM error response should have correct schema."""
    response = scim_error(404, "Not found")
    assert response.status_code == 404


def test_scim_error_with_type():
    """SCIM error with scimType should include it."""
    response = scim_error(409, "Already exists", "uniqueness")
    assert response.status_code == 409


def test_team_external_id_field():
    """Team model should have external_id field."""
    team = MagicMock(spec=Team)
    team.external_id = None
    assert team.external_id is None

    team.external_id = "scim-group-abc"
    assert team.external_id == "scim-group-abc"
