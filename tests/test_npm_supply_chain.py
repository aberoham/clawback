"""npm supply-chain detection: lockfiles, installed packages, IoC feeds.

Only npm's JSON lockfiles are parsed; yarn/pnpm/bun projects are covered via
their installed packages, which is what actually decides whether a lifecycle
hook ran. Both halves are exercised here.
"""
from __future__ import annotations

import json
import time

import pytest

import rattlesnake
from rattlesnake import (
    ScanContext,
    _iter_lockfile_entries,
    load_ioc_file,
    scan_npm_supply_chain,
)

BAD, BAD_VERSION = "keyv", "6.0.0"
SAFE_VERSION = "4.5.4"


@pytest.fixture
def project(tmp_path):
    """A project root under a scanned directory, plus its ScanContext."""
    root = tmp_path / "Projects" / "app"
    root.mkdir(parents=True)
    (root / "package.json").write_text(json.dumps({"name": "app"}))
    ctx = ScanContext(
        home=tmp_path, username="u", hostname="h", start_time=time.monotonic(),
    )
    return root, ctx


def _scan(ctx):
    scan_npm_supply_chain(ctx, quiet=True)
    return [f for f in ctx.findings if f.category == "npm_supply_chain"]


def _pkgs(findings):
    return {(f.details.get("package"), f.details.get("version")) for f in findings}


def _reasons(ctx):
    return [o.details.get("reason") for o in ctx.observations]


def _install(root, name, version, scripts=None, tree="node_modules"):
    pkg = root / tree
    for part in name.split("/"):
        pkg = pkg / part
    pkg.mkdir(parents=True)
    manifest = {"name": name, "version": version}
    if scripts is not None:
        manifest["scripts"] = scripts
    (pkg / "package.json").write_text(json.dumps(manifest))
    return pkg


# -------------------------------------------------------------------
# npm lockfiles
# -------------------------------------------------------------------


class TestNpmLockfiles:
    def test_v1_nested_dependencies(self, project):
        """npm 6-era lockfiles have no "packages" map at all."""
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "parent": {
                    "version": "1.0.0",
                    "dependencies": {BAD: {"version": BAD_VERSION}},
                },
            },
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_v3_packages_map(self, project):
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_shrinkwrap_is_scanned(self, project):
        root, ctx = project
        (root / "npm-shrinkwrap.json").write_text(json.dumps({
            "lockfileVersion": 2,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_v3_alias_resolves_via_manifest_name(self, project):
        """The tree path is the alias; the real package is in meta["name"]."""
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {
                "node_modules/innocent": {"name": BAD, "version": BAD_VERSION},
            },
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_v1_alias_encoded_in_version(self, project):
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "innocent": {"version": f"npm:{BAD}@{BAD_VERSION}"},
            },
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_dependencies_beneath_an_alias_are_walked(self, project):
        """An alias entry can carry its own dependency subtree."""
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                "alias": {
                    "version": "npm:other@1.0.0",
                    "dependencies": {BAD: {"version": BAD_VERSION}},
                },
            },
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_safe_version_is_not_flagged(self, project):
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {
                BAD: {"version": SAFE_VERSION},
                "flat-cache": {"version": "3.2.0"},
                "file-entry-cache": {"version": "6.0.1"},
            },
        }))

        assert _scan(ctx) == []

    def test_remediation_names_the_safe_pin_and_rejects_the_attacker_tag(
        self, project
    ):
        """6.0.1 was created by the attacker, so it is not an upgrade path."""
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))

        remediation = _scan(ctx)[0].remediation
        assert "5.6.0" in remediation
        assert "6.0.1" in remediation
        # Watcher shutdown must precede revocation in the raw JSON too.
        assert remediation.index("gh-token-monitor") < remediation.index("revoke")

    def test_affected_scope_is_an_observation_not_a_finding(self, project):
        """Most versions in an affected scope are clean."""
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {"node_modules/@qlik/api": {"version": "2.14.1"}},
        }))

        assert _scan(ctx) == []
        assert "compromised_scope_present" in _reasons(ctx)


class TestForeignLockfilesAreNotParsed:
    @pytest.mark.parametrize("lockfile,body", [
        ("yarn.lock", 'keyv@^6.0.0:\n  version "6.0.0"\n'),
        ("pnpm-lock.yaml", "packages:\n  /keyv@6.0.0:\n    resolution: {}\n"),
        ("bun.lock", '{"packages": {"keyv": ["keyv@6.0.0", "", {}, "sha512-x"]}}'),
    ])
    def test_installed_packages_still_cover_them(
        self, project, lockfile, body
    ):
        """The lockfile is ignored; the installed tree is what is inspected."""
        root, ctx = project
        (root / lockfile).write_text(body)
        _install(root, BAD, BAD_VERSION)

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_uninstalled_project_is_reported_as_unverified(self, project):
        """The residual gap is stated rather than passed off as clean."""
        root, ctx = project
        (root / "yarn.lock").write_text('keyv@^6.0.0:\n  version "6.0.0"\n')

        assert _scan(ctx) == []
        assert "lockfile_not_parsed" in _reasons(ctx)

    def test_no_observation_once_dependencies_are_installed(self, project):
        root, ctx = project
        (root / "pnpm-lock.yaml").write_text("packages:\n  /x@1.0.0:\n")
        _install(root, "x", "1.0.0")

        _scan(ctx)
        assert "lockfile_not_parsed" not in _reasons(ctx)


class TestHostileLockfileInput:
    @pytest.mark.parametrize("blob", [
        "{not valid json",
        '{"lockfileVersion": 3, "packages": "not-an-object"}',
        '{"lockfileVersion": 1, "dependencies": ["a", "b"]}',
        '{"lockfileVersion": 3, "packages": 42}',
    ])
    def test_recorded_as_a_gap_without_raising(self, project, blob):
        root, ctx = project
        (root / "package-lock.json").write_text(blob)

        scan_npm_supply_chain(ctx, quiet=True)  # must not raise

        assert any("NOT scanned" in g for g in ctx.coverage_gaps)

    def test_one_bad_lockfile_does_not_end_the_category(self, tmp_path):
        bad = tmp_path / "Projects" / "aaa-bad"
        bad.mkdir(parents=True)
        (bad / "package.json").write_text("{}")
        (bad / "package-lock.json").write_text('{"packages": "nope"}')

        good = tmp_path / "Projects" / "zzz-good"
        good.mkdir(parents=True)
        (good / "package.json").write_text("{}")
        (good / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))

        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )
        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))
        assert ctx.coverage_gaps

    def test_oversize_lockfile_is_reported(self, project, monkeypatch):
        root, ctx = project
        monkeypatch.setattr(rattlesnake, "LOCKFILE_MAX_BYTES", 64)
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))

        scan_npm_supply_chain(ctx, quiet=True)

        assert any("NOT scanned" in g for g in ctx.coverage_gaps)

    def test_parser_raises_for_the_caller_to_record(self, tmp_path):
        with pytest.raises((ValueError, TypeError)):
            _iter_lockfile_entries(tmp_path / "package-lock.json", "{nope")


# -------------------------------------------------------------------
# Installed packages
# -------------------------------------------------------------------


class TestInstalledPackages:
    def test_compromised_version_without_any_lockfile(self, project):
        """git/tarball installs, or a tree whose loader was already deleted."""
        root, ctx = project
        _install(root, BAD, BAD_VERSION)

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_aliased_directory_uses_the_manifest_name(self, project):
        root, ctx = project
        pkg = root / "node_modules" / "harmless"
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(json.dumps({
            "name": "cacheable", "version": "2.5.1",
        }))

        assert ("cacheable", "2.5.1") in _pkgs(_scan(ctx))

    @pytest.mark.parametrize("tree", [
        "node_modules/parent/node_modules",
        "node_modules/@scope/parent/node_modules",
        "node_modules/.pnpm/keyv@6.0.0/node_modules",
    ])
    def test_nested_and_virtual_trees_are_traversed(self, project, tree):
        """Version conflicts and pnpm both place packages off the top level."""
        root, ctx = project
        _install(root, BAD, BAD_VERSION, tree=tree)

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_scoped_package_in_the_pnpm_store(self, project):
        root, ctx = project
        _install(root, "@keyv/redis", "6.0.0",
                 tree="node_modules/.pnpm/@keyv+redis@6.0.0/node_modules")

        assert ("@keyv/redis", "6.0.0") in _pkgs(_scan(ctx))

    def test_large_manifest_is_read_whole(self, project):
        """date-fns ships a package.json over 64 KB via its exports map."""
        root, ctx = project
        pkg = root / "node_modules" / BAD
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(json.dumps({
            "name": BAD, "version": BAD_VERSION,
            "exports": {f"./m{i}": f"./dist/m{i}.js" for i in range(4000)},
        }))

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))
        assert ctx.coverage_gaps == []

    def test_clean_tree_is_silent(self, project):
        root, ctx = project
        _install(root, BAD, SAFE_VERSION)

        assert _scan(ctx) == []
        assert ctx.errors == [] and ctx.coverage_gaps == []


class TestPreinstallNeedsCorroboration:
    def test_filename_alone_is_only_an_observation(self, project):
        """`preinstall: node setup.mjs` is also an ordinary build step."""
        root, ctx = project
        pkg = _install(root, "healthy", "1.0.0",
                       scripts={"preinstall": "node setup.mjs"})
        (pkg / "setup.mjs").write_text("// ordinary bootstrap\n")

        assert _scan(ctx) == []
        assert "preinstall_dropper_name_unverified" in _reasons(ctx)

    def test_matching_payload_hash_confirms(self, project, monkeypatch):
        root, ctx = project
        pkg = _install(root, "unlisted-pkg", "9.9.9",
                       scripts={"preinstall": "node setup.mjs"})
        payload = pkg / "setup.mjs"
        payload.write_text("// simulated payload\n")
        monkeypatch.setitem(
            rattlesnake.KNOWN_MALWARE_SHA256,
            rattlesnake.sha256_file(payload), "test payload",
        )

        hits = [f for f in _scan(ctx) if "preinstall" in f.description]
        assert hits and hits[0].details["corroboration"] == "payload_hash"

    def test_compromised_version_confirms(self, project):
        root, ctx = project
        _install(root, "flat-cache", "6.1.24",
                 scripts={"preinstall": "node setup.mjs"})

        hits = [f for f in _scan(ctx) if "preinstall" in f.description]
        assert hits
        assert hits[0].details["corroboration"] == "compromised_version"
        assert "BEFORE revoking" in hits[0].remediation

    def test_payload_hash_matches_anywhere_in_the_tree(self, project, monkeypatch):
        root, ctx = project
        pkg = _install(root, "x", "1.0.0",
                       tree="node_modules/.pnpm/x@1.0.0/node_modules")
        payload = pkg / "setup.mjs"
        payload.write_text("// simulated payload\n")
        monkeypatch.setitem(
            rattlesnake.KNOWN_MALWARE_SHA256,
            rattlesnake.sha256_file(payload), "test payload",
        )

        assert [f for f in _scan(ctx) if f.severity == "critical"]


class TestHostileManifests:
    @pytest.mark.parametrize("scripts", ["a string", [1, 2], 42])
    def test_non_object_scripts_does_not_abort_the_tree(self, project, scripts):
        """An AttributeError here used to abandon every remaining package."""
        root, ctx = project
        _install(root, "evil", "1.0.0", scripts=scripts)
        _install(root, BAD, BAD_VERSION)

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_unreadable_manifest_is_reported(self, project):
        root, ctx = project
        pkg = _install(root, BAD, BAD_VERSION)
        (pkg / "package.json").chmod(0o000)

        try:
            scan_npm_supply_chain(ctx, quiet=True)
            assert any("could not read" in g for g in ctx.coverage_gaps)
        finally:
            (pkg / "package.json").chmod(0o644)

    def test_absent_manifest_is_not_a_gap(self, project):
        root, ctx = project
        (root / "node_modules" / "no-manifest").mkdir(parents=True)

        scan_npm_supply_chain(ctx, quiet=True)

        assert ctx.coverage_gaps == []

    def test_unreadable_tree_fails_closed(self, project):
        root, ctx = project
        modules = root / "node_modules"
        _install(root, BAD, BAD_VERSION)
        modules.chmod(0o000)

        try:
            scan_npm_supply_chain(ctx, quiet=True)
            assert any("NOT scanned" in g for g in ctx.coverage_gaps)
        finally:
            modules.chmod(0o755)

    def test_package_cap_truncation_is_reported(self, project, monkeypatch):
        root, ctx = project
        for i in range(5):
            _install(root, f"p{i}", "1.0.0")
        monkeypatch.setattr(rattlesnake, "NPM_MAX_PACKAGES_PER_TREE", 2)

        scan_npm_supply_chain(ctx, quiet=True)

        assert any("NOT scanned" in g for g in ctx.coverage_gaps)


class TestGlobalInstalls:
    @pytest.mark.parametrize("rel", [
        ".npm-global/lib/node_modules",
        ".nvm/versions/node/v20.0.0/lib/node_modules",
        ".volta/tools/image/node/20.0.0/lib/node_modules",
    ])
    def test_global_layouts_are_scanned(self, tmp_path, rel):
        """`npm install -g` lands outside every project root."""
        pkg = tmp_path / rel / BAD
        pkg.mkdir(parents=True)
        (pkg / "package.json").write_text(json.dumps({
            "name": BAD, "version": BAD_VERSION,
        }))
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_absent_global_root_is_harmless(self, tmp_path):
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        scan_npm_supply_chain(ctx, quiet=True)

        assert ctx.errors == [] and ctx.coverage_gaps == []


# -------------------------------------------------------------------
# Discovery and posture
# -------------------------------------------------------------------


class TestDiscovery:
    def test_project_in_a_hidden_directory_is_scanned(self, tmp_path):
        root = tmp_path / ".dotfiles" / "app"
        root.mkdir(parents=True)
        (root / "package.json").write_text("{}")
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_symlink_cycle_does_not_exhaust_the_budget(self, tmp_path):
        root = tmp_path / "Projects" / "app"
        root.mkdir(parents=True)
        (root / "package.json").write_text("{}")
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 3,
            "packages": {f"node_modules/{BAD}": {"version": BAD_VERSION}},
        }))
        try:
            (root / "loop").symlink_to(tmp_path / "Projects")
        except OSError:
            pytest.skip("symlinks unavailable")
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        assert (BAD, BAD_VERSION) in _pkgs(_scan(ctx))

    def test_truncated_discovery_is_reported(self, tmp_path, monkeypatch):
        for i in range(6):
            d = tmp_path / "Projects" / f"app{i}"
            d.mkdir(parents=True)
            (d / "package.json").write_text("{}")
        monkeypatch.setattr(rattlesnake, "SUPPLY_CHAIN_MAX_DIRS", 2)
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        scan_npm_supply_chain(ctx, quiet=True)

        assert any("NOT scanned" in g for g in ctx.coverage_gaps)

    @pytest.mark.parametrize("junk", ["__MACOSX", ".Spotlight-V100", ".dolt"])
    def test_metadata_and_database_dirs_are_pruned(self, tmp_path, junk):
        """Unreadable and irrelevant: a gap here would be permanent noise."""
        blocked = tmp_path / "Documents" / junk
        blocked.mkdir(parents=True)
        blocked.chmod(0o000)
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        try:
            scan_npm_supply_chain(ctx, quiet=True)
            assert ctx.coverage_gaps == [] and ctx.errors == []
        finally:
            blocked.chmod(0o755)

    def test_a_real_unreadable_project_dir_is_still_a_gap(self, tmp_path):
        """The prune must not become a blanket excuse for silence."""
        blocked = tmp_path / "Documents" / "realwork"
        blocked.mkdir(parents=True)
        (blocked / "inner").mkdir()
        blocked.chmod(0o000)
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        try:
            scan_npm_supply_chain(ctx, quiet=True)
            assert ctx.coverage_gaps
        finally:
            blocked.chmod(0o755)


class TestInstallScriptPosture:
    def test_disabled_scripts_recorded_as_hardened(self, tmp_path):
        (tmp_path / ".npmrc").write_text("ignore-scripts=true\n")
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        scan_npm_supply_chain(ctx, quiet=True)

        assert "hardened_install_posture" in _reasons(ctx)

    def test_default_posture_is_an_observation_not_a_finding(self, tmp_path):
        """npm's default must not push every healthy host to exit 1."""
        ctx = ScanContext(
            home=tmp_path, username="u", hostname="h",
            start_time=time.monotonic(),
        )

        scan_npm_supply_chain(ctx, quiet=True)

        assert "default_install_posture" in _reasons(ctx)
        assert ctx.findings == []


# -------------------------------------------------------------------
# --ioc-file
# -------------------------------------------------------------------


class TestIocFile:
    def test_extends_detection_to_the_campaign_tail(self, project, tmp_path):
        root, ctx = project
        (root / "package-lock.json").write_text(json.dumps({
            "lockfileVersion": 1,
            "dependencies": {"@ornikar/eslint-config": {"version": "24.0.1"}},
        }))
        ioc = tmp_path / "iocs.json"
        ioc.write_text(json.dumps({
            "packages": {"@ornikar/eslint-config": ["24.0.1"]},
        }))
        extra, error = load_ioc_file(str(ioc))
        assert error is None
        ctx.extra_iocs = extra

        assert ("@ornikar/eslint-config", "24.0.1") in _pkgs(_scan(ctx))

    def test_string_version_is_accepted(self, tmp_path):
        ioc = tmp_path / "iocs.json"
        ioc.write_text(json.dumps({"packages": {"p": "1.0.0"}}))

        assert load_ioc_file(str(ioc)) == ({"p": ("1.0.0",)}, None)

    def test_wholly_unusable_feed_is_an_error(self, tmp_path):
        """A feed that loads nothing must not look like a success."""
        ioc = tmp_path / "iocs.json"
        ioc.write_text(json.dumps({
            "packages": {"keyv": {"bad": "shape"}, "flat-cache": 12345},
        }))

        extra, error = load_ioc_file(str(ioc))

        assert extra == {}
        assert error and "no usable entries" in error

    def test_partial_feed_loads_and_warns(self, tmp_path):
        ioc = tmp_path / "iocs.json"
        ioc.write_text(json.dumps({
            "packages": {"keyv": ["6.0.0"], "broken": {"x": 1}},
        }))

        extra, error = load_ioc_file(str(ioc))

        assert extra == {"keyv": ("6.0.0",)}
        assert error and "malformed" in error

    @pytest.mark.parametrize("content", [
        "{not json", '{"packages": []}', "", '{"packages": {}}',
    ])
    def test_malformed_feed_errors_without_raising(self, tmp_path, content):
        ioc = tmp_path / "iocs.json"
        ioc.write_text(content)

        extra, error = load_ioc_file(str(ioc))

        assert extra == {} and error is not None

    def test_missing_file_errors(self, tmp_path):
        extra, error = load_ioc_file(str(tmp_path / "nope.json"))

        assert extra == {} and error is not None


class TestHashUtility:
    def test_oversize_file_is_skipped(self, tmp_path):
        big = tmp_path / "big.js"
        big.write_bytes(b"x" * 2048)

        assert rattlesnake.sha256_file(big, max_bytes=1024) is None
        assert rattlesnake.sha256_file(big, max_bytes=4096) is not None

    def test_missing_file_returns_none(self, tmp_path):
        assert rattlesnake.sha256_file(tmp_path / "absent.js") is None
