from nexora.sandbox_readiness import inspect_sandbox_readiness


def test_sandbox_readiness_never_authorizes_execution():
    report = inspect_sandbox_readiness(
        system="Linux", release="6.8.0", bubblewrap_path="/usr/bin/bwrap",
    )
    assert report["status"] == "UNVERIFIED"
    assert report["backend"] == "bubblewrap"
    assert report["execution_enabled"] is False
    assert report["execution_authorized"] is False
    assert report["fallback_to_unsandboxed_execution"] is False
    assert report["checks"]["user_namespace_creation"]["status"] == "UNVERIFIED"
    assert report["checks"]["adversarial_backend_validation"]["status"] == "UNVERIFIED"


def test_missing_backend_is_unavailable_and_fail_closed():
    report = inspect_sandbox_readiness(
        system="Linux", release="6.8.0", bubblewrap_path=None,
    )
    assert report["status"] == "UNAVAILABLE"
    assert "bubblewrap_binary" in report["blockers"]
    assert report["execution_enabled"] is False


def test_android_is_not_qualified_even_with_bubblewrap():
    report = inspect_sandbox_readiness(
        system="Linux", release="6.1.0-android14", bubblewrap_path="/usr/bin/bwrap",
    )
    assert report["status"] == "UNAVAILABLE"
    assert report["checks"]["linux_host"]["status"] == "FAIL"
    assert report["execution_authorized"] is False


def test_non_linux_host_is_unavailable():
    report = inspect_sandbox_readiness(
        system="Windows", release="10", bubblewrap_path="C:/tools/bwrap.exe",
    )
    assert report["status"] == "UNAVAILABLE"
    assert report["execution_enabled"] is False
