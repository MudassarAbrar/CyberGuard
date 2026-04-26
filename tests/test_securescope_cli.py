from pathlib import Path
from typer.testing import CliRunner

from cli.main import app

runner = CliRunner()


def test_version_command():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "SecureScope version" in result.stdout
    assert "0.1.0" in result.stdout


def test_init_command(tmp_path):
    # Change the current working directory to the temporary path for this test
    # so we don't pollute the actual project directory.
    import os
    original_cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        result = runner.invoke(app, ["init"])
        assert result.exit_code == 0
        assert "Created configuration file" in result.stdout

        config_path = tmp_path / ".securescope.yml"
        assert config_path.exists()

        # Test that running it again fails
        result2 = runner.invoke(app, ["init"])
        assert result2.exit_code == 1
        assert "already exists" in result2.output
    finally:
        os.chdir(original_cwd)


def test_scan_command_basic(tmp_path):
    test_dir = tmp_path / "test_project"
    test_dir.mkdir()

    result = runner.invoke(app, ["scan", str(test_dir), "--fail-on", "critical"])
    # The mock has a critical finding, so it will fail when fail-on is critical or lower.
    # But wait, wait, fail_on="critical" means it fails if findings are >= critical.
    # Mock finding has a critical issue, so it will exit 1.
    assert result.exit_code == 1
    assert "SecureScope Scan Started" in result.stdout
    assert "Scan complete!" in result.stdout


def test_scan_command_no_ai_and_json(tmp_path):
    test_dir = tmp_path / "test_project"
    test_dir.mkdir()

    result = runner.invoke(app, ["scan", str(test_dir), "--no-ai", "--format", "json", "--fail-on", "critical"])

    # Still fails because there's a critical finding in the mock
    assert result.exit_code == 1
    assert "Output would be saved as json" in result.stdout
    # Check that it skipped AI (AI engine is not mentioned as running, though the mock doesn't print "Skipping AI" explicitly,
    # the progress bar is mocked but we can't easily capture it).

def test_scan_fail_on_info(tmp_path):
    test_dir = tmp_path / "test_project"
    test_dir.mkdir()

    result = runner.invoke(app, ["scan", str(test_dir), "--fail-on", "info"])
    assert result.exit_code == 1
    assert "Findings found at or above info severity" in result.stdout
