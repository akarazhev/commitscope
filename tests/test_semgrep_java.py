"""Regression checks for the small bundled Java Semgrep baseline."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from sec_review.tools import semgrep_child_env
from sec_review.core import trusted_internal_temp_path

EXPECTED = {
    "sr-java-sql-construction",
    "sr-java-process-exec",
    "sr-java-deserialization",
    "sr-java-tls-hostname-disabled",
    "sr-java-tls-trust-disabled",
}


class JavaBaselineTests(unittest.TestCase):
    def test_java_rules_are_present(self):
        rules = json.loads((ROOT / "config/semgrep.yaml").read_text())["rules"]
        actual = {rule["id"] for rule in rules if "java" in rule["languages"]}
        self.assertEqual(actual, EXPECTED)

    @unittest.skipUnless(os.environ.get("COMMITSCOPE_TEST_SEMGREP"), "real Semgrep not configured")
    def test_scanner_command_uses_staged_config_with_stable_rule_ids(self):
        from sec_review.scanners import semgrep_command

        binary = Path(os.environ["COMMITSCOPE_TEST_SEMGREP"])
        with tempfile.TemporaryDirectory(
            dir=trusted_internal_temp_path(Path(tempfile.gettempdir()))
        ) as directory:
            root = Path(directory)
            runner = root / "runner"
            source = root / "source"
            raw = root / "raw"
            home = root / "home"
            for path in (runner, source, raw, home):
                path.mkdir()
            (source / "Vulnerable.java").write_text(
                "class Vulnerable { void run(String command) throws Exception { "
                "Runtime.getRuntime().exec(command); } }\n"
            )
            command = semgrep_command(source, raw, ROOT, runner, binary)
            result = subprocess.run(
                command, cwd=runner, capture_output=True, text=True, timeout=120,
                env=semgrep_child_env(binary.parent.parent.parent, home),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads((raw / "semgrep.json").read_text())
        self.assertFalse(data["errors"], data["errors"])
        self.assertEqual([item["check_id"] for item in data["results"]],
                         ["config.sr-java-process-exec"])

    @unittest.skipUnless(os.environ.get("COMMITSCOPE_TEST_SEMGREP"), "real Semgrep not configured")
    def test_real_semgrep_finds_vulnerable_java_and_ignores_fixed_java(self):
        vulnerable = """\
import java.io.ObjectInputStream;
import java.sql.Statement;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

class Vulnerable {
    void sql(Statement statement, String name) throws Exception {
        statement.executeQuery("SELECT * FROM users WHERE name='" + name + "'");
    }
    void process(String command) throws Exception {
        Runtime.getRuntime().exec(command);
    }
    Object deserialize(ObjectInputStream input) throws Exception {
        return input.readObject();
    }
    void tls() {
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        X509TrustManager trust = new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() { return null; }
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        };
    }
}
"""
        fixed = """\
import java.io.DataInputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import javax.net.ssl.HttpsURLConnection;

class Fixed {
    void sql(Connection connection, String name) throws Exception {
        PreparedStatement statement = connection.prepareStatement("SELECT * FROM users WHERE name=?");
        statement.setString(1, name);
        statement.executeQuery();
    }
    String deserialize(DataInputStream input) throws Exception {
        return input.readUTF();
    }
    void tls() {
        HttpsURLConnection.getDefaultHostnameVerifier();
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            home = root / "home"
            home.mkdir()
            (root / "Vulnerable.java").write_text(vulnerable)
            (root / "Fixed.java").write_text(fixed)
            binary = Path(os.environ["COMMITSCOPE_TEST_SEMGREP"])
            command = [
                str(binary), "scan", "--config",
                str(ROOT / "config/semgrep.yaml"), "--oss-only", "--json",
                "--metrics", "off", "--disable-version-check", "--disable-nosem",
                "--no-git-ignore", "--strict", str(root),
            ]
            result = subprocess.run(
                command, capture_output=True, text=True, timeout=120,
                env=semgrep_child_env(binary.parent.parent.parent, home),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
        self.assertFalse(data["errors"], data["errors"])
        self.assertEqual({Path(path).name for path in data["paths"]["scanned"]},
                         {"Vulnerable.java", "Fixed.java"})
        matches = {item["check_id"].split(".")[-1] for item in data["results"]
                   if Path(item["path"]).name == "Vulnerable.java"}
        self.assertEqual(matches, EXPECTED)
        self.assertFalse([item for item in data["results"]
                          if Path(item["path"]).name == "Fixed.java"])


if __name__ == "__main__":
    unittest.main()
