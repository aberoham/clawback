"""Tests for scan categories: cloud, git, package manager, k8s, crypto, secrets manager."""
from __future__ import annotations

import json

import pytest

import clawback
from clawback import (
    scan_cloud_credentials,
    scan_crypto_wallets,
    scan_git_credentials,
    scan_kubernetes,
    scan_package_manager_tokens,
    scan_secrets_manager_status,
)


# -------------------------------------------------------------------
# AWS
# -------------------------------------------------------------------


class TestScanAws:
    def test_credentials_file_high(self, scan_ctx, clean_env):
        aws = scan_ctx.home / ".aws"
        aws.mkdir()
        (aws / "credentials").write_text(
            "[default]\n"
            "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
            "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCY\n"
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "credentials file" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_config_only_observation(self, scan_ctx, clean_env):
        aws = scan_ctx.home / ".aws"
        aws.mkdir()
        (aws / "config").write_text("[default]\nregion = us-east-1\n")
        scan_cloud_credentials(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        aws_obs = [
            o for o in scan_ctx.observations
            if o.category == "cloud_credentials"
        ]
        assert len(aws_obs) >= 1

    def test_env_akia_critical(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setenv(
            "AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE"
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "AWS_ACCESS_KEY_ID" in f.description
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"


# -------------------------------------------------------------------
# GCP
# -------------------------------------------------------------------


class TestScanGcp:
    def test_service_account_adc_critical(self, scan_ctx, clean_env):
        gcloud = scan_ctx.home / ".config" / "gcloud"
        gcloud.mkdir(parents=True)
        (gcloud / "application_default_credentials.json").write_text(
            json.dumps({"type": "service_account", "project_id": "test"})
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "service account" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_authorized_user_adc_high(self, scan_ctx, clean_env):
        gcloud = scan_ctx.home / ".config" / "gcloud"
        gcloud.mkdir(parents=True)
        (gcloud / "application_default_credentials.json").write_text(
            json.dumps({"type": "authorized_user"})
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "gcp" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_gcloud_dir_no_adc_observation(self, scan_ctx, clean_env):
        gcloud = scan_ctx.home / ".config" / "gcloud"
        gcloud.mkdir(parents=True)
        scan_cloud_credentials(scan_ctx, quiet=True)
        gcp_obs = [
            o for o in scan_ctx.observations
            if "gcloud" in o.description.lower()
        ]
        assert len(gcp_obs) >= 1

    def test_google_creds_env_high(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setenv(
            "GOOGLE_APPLICATION_CREDENTIALS", "/path/to/key.json"
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "GOOGLE_APPLICATION_CREDENTIALS" in f.description
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_google_creds_env_op_ref_no_finding(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setenv(
            "GOOGLE_APPLICATION_CREDENTIALS", "op://vault/gcp/key"
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "GOOGLE_APPLICATION_CREDENTIALS" in f.description
        ]
        assert len(findings) == 0


# -------------------------------------------------------------------
# Azure
# -------------------------------------------------------------------


class TestScanAzure:
    def test_access_tokens_high(self, scan_ctx, clean_env):
        azure = scan_ctx.home / ".azure"
        azure.mkdir()
        (azure / "accessTokens.json").write_text('{"tokens": []}')
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "azure" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_client_secret_env_critical(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setenv(
            "AZURE_CLIENT_SECRET",
            "aB3kL9mNpQ7rS1tU5vW8xY0zA2cD4eF6gH",
        )
        scan_cloud_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "AZURE_CLIENT_SECRET" in f.description
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"


# -------------------------------------------------------------------
# Git credentials
# -------------------------------------------------------------------


class TestScanGitCredentials:
    def test_git_credentials_critical(self, scan_ctx, clean_env):
        (scan_ctx.home / ".git-credentials").write_text(
            "https://user:pass123@github.com\n"
        )
        scan_git_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "plaintext git credentials" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_gitconfig_store_helper_high(self, scan_ctx, clean_env):
        (scan_ctx.home / ".gitconfig").write_text(
            "[credential]\n\thelper = store\n"
        )
        scan_git_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "plaintext store" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_gitconfig_osxkeychain_observation(self, scan_ctx, clean_env):
        (scan_ctx.home / ".gitconfig").write_text(
            "[credential]\n\thelper = osxkeychain\n"
        )
        scan_git_credentials(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        obs = [
            o for o in scan_ctx.observations
            if "keychain" in o.description.lower()
        ]
        assert len(obs) == 1

    def test_netrc_with_password_high(self, scan_ctx, clean_env):
        (scan_ctx.home / ".netrc").write_text(
            "machine github.com\n"
            "login user\n"
            "password ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh\n"
        )
        scan_git_credentials(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if ".netrc" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"


# -------------------------------------------------------------------
# Package manager tokens
# -------------------------------------------------------------------


class TestScanPackageManagerTokens:
    def test_npmrc_auth_token_critical(self, scan_ctx, clean_env):
        (scan_ctx.home / ".npmrc").write_text(
            "//registry.npmjs.org/:_authToken=npm_1234567890abcdef\n"
        )
        scan_package_manager_tokens(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings if "npm" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_pypirc_password_high(self, scan_ctx, clean_env):
        (scan_ctx.home / ".pypirc").write_text(
            "[pypi]\n"
            "username = __token__\n"
            "password = pypi-AgEIcHlwaS5vcmcCJGI0MDAwMDAwMDAwMDAwMDAwMDAwMDA\n"
        )
        scan_package_manager_tokens(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings if "pypi" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_docker_plaintext_auth_critical(self, scan_ctx, clean_env):
        docker = scan_ctx.home / ".docker"
        docker.mkdir()
        (docker / "config.json").write_text(
            json.dumps({
                "auths": {
                    "https://index.docker.io/v1/": {
                        "auth": "dXNlcjpwYXNz"
                    }
                }
            })
        )
        scan_package_manager_tokens(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "docker" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_docker_credsstore_observation(self, scan_ctx, clean_env):
        docker = scan_ctx.home / ".docker"
        docker.mkdir()
        (docker / "config.json").write_text(
            json.dumps({"credsStore": "osxkeychain"})
        )
        scan_package_manager_tokens(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        obs = [
            o for o in scan_ctx.observations
            if "credential store" in o.description.lower()
        ]
        assert len(obs) == 1

    def test_gem_credentials_high(self, scan_ctx, clean_env):
        gem = scan_ctx.home / ".gem"
        gem.mkdir()
        (gem / "credentials").write_text(":rubygems_api_key: abc123\n")
        scan_package_manager_tokens(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "rubygems" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_cargo_credentials_high(self, scan_ctx, clean_env):
        cargo = scan_ctx.home / ".cargo"
        cargo.mkdir()
        (cargo / "credentials.toml").write_text(
            '[registry]\ntoken = "cio_abc123"\n'
        )
        scan_package_manager_tokens(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if "cargo" in f.description.lower()
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"


# -------------------------------------------------------------------
# Kubernetes
# -------------------------------------------------------------------


class TestScanKubernetes:
    def test_embedded_token_critical(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "_check_cert_expiry", lambda _: None)
        kube = scan_ctx.home / ".kube"
        kube.mkdir()
        (kube / "config").write_text(
            "apiVersion: v1\n"
            "clusters: []\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            "    token: eyJhbGciOiJSUzI1NiJ9.abcdef\n"
        )
        scan_kubernetes(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if f.category == "kubernetes"
        ]
        assert len(findings) == 1
        assert findings[0].severity == "critical"

    def test_embedded_cert_data_high(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "_check_cert_expiry", lambda _: None)
        kube = scan_ctx.home / ".kube"
        kube.mkdir()
        (kube / "config").write_text(
            "apiVersion: v1\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            "    client-key-data: AAAA\n"
            "    client-certificate-data: BBBB\n"
        )
        scan_kubernetes(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if f.category == "kubernetes"
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_expired_cert_downgraded_to_low(
        self, scan_ctx, monkeypatch, clean_env
    ):
        """When embedded creds are cert-only and the cert is expired,
        severity is downgraded to LOW (useless to an attacker)."""
        monkeypatch.setattr(
            clawback, "_check_cert_expiry",
            lambda _: "Jan  1 00:00:00 2020 GMT",
        )
        kube = scan_ctx.home / ".kube"
        kube.mkdir()
        (kube / "config").write_text(
            "apiVersion: v1\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            "    client-key-data: AAAA\n"
            "    client-certificate-data: BBBB\n"
        )
        scan_kubernetes(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if f.category == "kubernetes"
        ]
        assert len(findings) == 1
        assert findings[0].severity == "low"
        assert findings[0].details["cert_expired"] is True
        assert "2020" in findings[0].details["cert_expiry"]

    def test_exec_auth_observation(self, scan_ctx, clean_env):
        kube = scan_ctx.home / ".kube"
        kube.mkdir()
        (kube / "config").write_text(
            "apiVersion: v1\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            "    exec:\n"
            "      command: aws\n"
        )
        scan_kubernetes(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0
        obs = [
            o for o in scan_ctx.observations
            if o.category == "kubernetes"
        ]
        assert len(obs) == 1

    def test_empty_kubeconfig_nothing(self, scan_ctx, clean_env):
        kube = scan_ctx.home / ".kube"
        kube.mkdir()
        (kube / "config").write_text(
            "apiVersion: v1\nclusters: []\nusers: []\n"
        )
        scan_kubernetes(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0

    def test_kubeconfig_env_override(
        self, scan_ctx, monkeypatch, clean_env
    ):
        monkeypatch.setattr(clawback, "_check_cert_expiry", lambda _: None)
        custom = scan_ctx.home / "custom-kube"
        custom.write_text(
            "apiVersion: v1\n"
            "users:\n"
            "- name: admin\n"
            "  user:\n"
            "    token: secret-token-value\n"
        )
        monkeypatch.setenv("KUBECONFIG", str(custom))
        scan_kubernetes(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 1
        assert scan_ctx.findings[0].severity == "critical"


# -------------------------------------------------------------------
# Crypto wallets
# -------------------------------------------------------------------


class TestScanCryptoWallets:
    def test_nonempty_wallet_high(self, scan_ctx, clean_env):
        exodus = (
            scan_ctx.home / "Library" / "Application Support" / "Exodus"
        )
        exodus.mkdir(parents=True)
        (exodus / "wallet.dat").write_text("data")
        scan_crypto_wallets(scan_ctx, quiet=True)
        findings = [
            f for f in scan_ctx.findings
            if f.category == "crypto_wallets"
        ]
        assert len(findings) == 1
        assert findings[0].severity == "high"

    def test_empty_wallet_dir_nothing(self, scan_ctx, clean_env):
        exodus = (
            scan_ctx.home / "Library" / "Application Support" / "Exodus"
        )
        exodus.mkdir(parents=True)
        scan_crypto_wallets(scan_ctx, quiet=True)
        assert len(scan_ctx.findings) == 0


# -------------------------------------------------------------------
# Secrets manager status
# -------------------------------------------------------------------


class TestScanSecretsManagerStatus:
    def test_op_installed_observation(
        self, scan_ctx, monkeypatch, clean_env
    ):
        def fake_run_cmd(args, timeout=5):
            if args == ["which", "op"]:
                return "/usr/local/bin/op\n"
            return None

        monkeypatch.setattr(clawback, "run_cmd", fake_run_cmd)
        scan_secrets_manager_status(scan_ctx, quiet=True)
        obs = [
            o for o in scan_ctx.observations
            if o.details.get("tool") == "1password"
        ]
        assert len(obs) == 1

    def test_nothing_installed(self, scan_ctx, monkeypatch, clean_env):
        monkeypatch.setattr(
            clawback, "run_cmd", lambda *a, **kw: None
        )
        scan_secrets_manager_status(scan_ctx, quiet=True)
        assert len(scan_ctx.observations) == 0
