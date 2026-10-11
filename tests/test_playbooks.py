import pytest

from hexswarm.playbooks import Playbook, builtin_playbooks, load_playbook, resolve_playbook


def test_builtin_playbooks_are_loadable():
    pbs = builtin_playbooks()
    assert "recon-only" in pbs
    assert "web-assessment" in pbs
    assert "full-engagement" in pbs


def test_recon_only_playbook_shape():
    pb = builtin_playbooks()["recon-only"]
    assert pb.phases == ["recon"]
    assert pb.max_risk_level == "active_recon"
    assert pb.goal  # non-empty


def test_full_engagement_runs_all_phases():
    pb = builtin_playbooks()["full-engagement"]
    assert pb.phases == ["recon", "scan", "exploit", "privesc"]
    assert pb.max_risk_level == "post_exploit"


def test_resolve_playbook_by_builtin_name():
    pb = resolve_playbook("web-assessment")
    assert pb.name == "web-assessment"
    assert "scan" in pb.phases


def test_resolve_playbook_by_file_path(tmp_path):
    custom = tmp_path / "custom.yaml"
    custom.write_text(
        "name: my-playbook\ndescription: d\ngoal: do the thing\nphases: [recon, scan]\n",
        encoding="utf-8",
    )
    pb = resolve_playbook(str(custom))
    assert pb.name == "my-playbook"
    assert pb.phases == ["recon", "scan"]


def test_load_playbook_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_playbook(tmp_path / "nope.yaml")


def test_playbook_defaults_phases_when_unspecified():
    pb = Playbook.from_dict({"name": "x", "goal": "g"})
    assert pb.phases == ["recon", "scan", "exploit", "privesc"]
    assert pb.max_risk_level is None
