"""Tests for the MCP tool classification engine."""

import pytest
from app.services.tool_classifier import classify_tools, ClassifiedTool, _classify_single


class TestClassifySingle:
    """Test individual tool classification."""

    def test_read_verbs(self):
        for name in ["get_user", "list_repos", "search_issues", "fetch_data", "find_records"]:
            assert _classify_single(name) == "read", f"Expected read for {name}"

    def test_write_verbs(self):
        for name in ["create_issue", "update_record", "send_message", "push_commit", "upload_file"]:
            assert _classify_single(name) == "write", f"Expected write for {name}"

    def test_delete_verbs(self):
        for name in ["delete_repo", "remove_member", "destroy_session", "purge_cache", "kill_process"]:
            assert _classify_single(name) == "delete", f"Expected delete for {name}"

    def test_description_fallback_read(self):
        assert _classify_single("my_tool", "Retrieves the latest data from the API") == "read"

    def test_description_fallback_write(self):
        assert _classify_single("my_tool", "Creates a new record in the database") == "write"

    def test_description_fallback_delete(self):
        assert _classify_single("my_tool", "Deletes the specified resource permanently") == "delete"

    def test_unknown_no_description(self):
        assert _classify_single("xyzzy") == "unknown"

    def test_kebab_case(self):
        assert _classify_single("get-items") == "read"

    def test_camel_case(self):
        assert _classify_single("createIssue") == "write"


class TestClassifyTools:
    """Test batch classification."""

    def test_string_tools(self):
        tools = ["get_users", "create_repo", "delete_branch"]
        result = classify_tools(tools)
        assert len(result) == 3
        assert result[0].category == "read"
        assert result[1].category == "write"
        assert result[2].category == "delete"

    def test_dict_tools(self):
        tools = [
            {"name": "get_users", "description": "List all users"},
            {"name": "create_repo", "description": "Create a new repository"},
        ]
        result = classify_tools(tools)
        assert len(result) == 2
        assert result[0].category == "read"
        assert result[1].category == "write"

    def test_empty_tools(self):
        assert classify_tools([]) == []

    def test_mixed_types(self):
        tools = ["get_data", {"name": "update_config"}, 42, None, ""]
        result = classify_tools(tools)
        assert len(result) == 2  # Skips non-string/dict and empty

    def test_dict_without_name(self):
        tools = [{"description": "Some tool"}]
        result = classify_tools(tools)
        assert len(result) == 0

    def test_description_helps_classify(self):
        tools = [{"name": "process_data", "description": "Fetches and retrieves data"}]
        result = classify_tools(tools)
        assert result[0].category == "read"


class TestRealWorldTools:
    """Test with real-world MCP tool names."""

    def test_github_tools(self):
        tools = [
            "get_repo", "list_issues", "create_issue", "update_issue",
            "delete_branch", "search_code", "create_pull_request",
            "merge_pull_request", "fork_repo",
        ]
        result = classify_tools(tools)
        categories = {t.name: t.category for t in result}
        assert categories["get_repo"] == "read"
        assert categories["list_issues"] == "read"
        assert categories["create_issue"] == "write"
        assert categories["delete_branch"] == "delete"
        assert categories["search_code"] == "read"
        assert categories["create_pull_request"] == "write"
        assert categories["fork_repo"] == "write"

    def test_filesystem_tools(self):
        tools = ["read_file", "write_file", "list_directory", "delete_file", "move_file"]
        result = classify_tools(tools)
        categories = {t.name: t.category for t in result}
        assert categories["read_file"] == "read"
        assert categories["write_file"] == "write"
        assert categories["list_directory"] == "read"
        assert categories["delete_file"] == "delete"
        assert categories["move_file"] == "write"

    def test_notion_tools(self):
        tools = [
            "search_pages", "get_page", "create_page", "update_page",
            "delete_page", "get_database", "query_database",
        ]
        result = classify_tools(tools)
        categories = {t.name: t.category for t in result}
        assert categories["search_pages"] == "read"
        assert categories["create_page"] == "write"
        assert categories["delete_page"] == "delete"
        assert categories["query_database"] == "read"
