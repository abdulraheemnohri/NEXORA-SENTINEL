import pytest
from nexora.budgets import BudgetExceeded, BudgetLedger
from nexora.config import Settings
from nexora.sandbox import SandboxError, StagingWorkspace
from nexora.scheduler import Scheduler
from nexora.tools import ToolBoundary, ToolContract
from nexora.workspace import Workspace

def test_settings_defaults_fail_closed():
    settings=Settings().validate()
    assert settings.autonomy_level=="L0"
    assert not settings.scheduler_enabled and not settings.sandbox_enabled and not settings.network_enabled

def test_settings_reject_unknown_autonomy():
    with pytest.raises(ValueError):
        Settings(autonomy_level="L9").validate()

def test_budget_is_atomic_and_enforced(tmp_path):
    ledger=BudgetLedger(tmp_path/"budget.sqlite3")
    assert ledger.consume("actions",2,limit=3,now=100)==2
    with pytest.raises(BudgetExceeded):
        ledger.consume("actions",2,limit=3,now=101)
    assert ledger.usage("actions",now=101)==2

def test_scheduler_claims_due_without_execution(tmp_path):
    scheduler=Scheduler(tmp_path/"jobs.sqlite3")
    job=scheduler.schedule("review",{"target":"patch"},due_at=100,now=90)
    assert scheduler.due(now=99)==[]
    due=scheduler.due(now=100)
    assert due[0]["id"]==job
    assert scheduler.due(now=100)==[]

def test_scheduler_cancel_pending(tmp_path):
    scheduler=Scheduler(tmp_path/"jobs.sqlite3")
    job=scheduler.schedule("review",{},due_at=200,now=100)
    assert scheduler.cancel(job)
    assert scheduler.due(now=300)==[]

def test_staging_workspace_rejects_escape_and_never_executes(tmp_path):
    stage=StagingWorkspace(tmp_path/"stage")
    result=stage.stage("proposal.txt",b"review me")
    assert result["execution"]=="DISABLED"
    with pytest.raises(SandboxError,match="path_escape_denied"):
        stage.stage("../escape.txt",b"bad")

def test_tool_boundary_only_queues_proposals(tmp_path):
    boundary=ToolBoundary(tmp_path/"tools.sqlite3")
    proposal=boundary.propose(ToolContract("filesystem.read","low","Read-only file read"),{"path":"README.md"})
    assert boundary.list_pending()[0]["id"]==proposal

def test_workspace_path_containment(tmp_path):
    workspace=Workspace(tmp_path/"workspace")
    assert workspace.resolve("notes/todo.md").is_relative_to(workspace.root)
    with pytest.raises(ValueError):
        workspace.resolve("../../outside")
