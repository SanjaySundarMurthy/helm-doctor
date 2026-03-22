"""Shared test fixtures for helm-doctor."""
import pytest


@pytest.fixture
def tmp_chart(tmp_path):
    """Factory fixture: creates a minimal valid Helm chart directory."""
    def _make(
        chart_yaml=None,
        values_yaml=None,
        templates=None,
        extra_files=None,
    ):
        chart_dir = tmp_path / "test-chart"
        chart_dir.mkdir(exist_ok=True)
        tpl_dir = chart_dir / "templates"
        tpl_dir.mkdir(exist_ok=True)

        # Default Chart.yaml
        if chart_yaml is None:
            chart_yaml = (
                "apiVersion: v2\n"
                "name: test-chart\n"
                "description: A test chart\n"
                "version: 1.0.0\n"
                "appVersion: '1.0.0'\n"
                "type: application\n"
                "maintainers:\n"
                "  - name: Test\n"
                "    email: test@example.com\n"
            )
        (chart_dir / "Chart.yaml").write_text(chart_yaml, encoding="utf-8")

        # Default values.yaml
        if values_yaml is None:
            values_yaml = (
                "replicaCount: 2\n"
                "image:\n"
                "  repository: nginx\n"
                "  tag: '1.25'\n"
                "  pullPolicy: IfNotPresent\n"
                "resources:\n"
                "  limits:\n"
                "    cpu: 500m\n"
                "    memory: 256Mi\n"
                "  requests:\n"
                "    cpu: 100m\n"
                "    memory: 128Mi\n"
            )
        (chart_dir / "values.yaml").write_text(values_yaml, encoding="utf-8")

        # Default deployment template
        if templates is None:
            templates = {
                "deployment.yaml": (
                    "apiVersion: apps/v1\n"
                    "kind: Deployment\n"
                    "metadata:\n"
                    "  name: {{ include \"test.fullname\" . }}\n"
                    "spec:\n"
                    "  replicas: {{ .Values.replicaCount }}\n"
                )
            }
        for name, content in templates.items():
            (tpl_dir / name).write_text(content, encoding="utf-8")

        if extra_files:
            for name, content in extra_files.items():
                fpath = chart_dir / name
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content, encoding="utf-8")

        return str(chart_dir)

    return _make


@pytest.fixture
def good_chart(tmp_chart):
    """A well-structured chart that passes most checks."""
    return tmp_chart()


@pytest.fixture
def bad_chart(tmp_chart):
    """A chart with many issues for testing detection."""
    return tmp_chart(
        chart_yaml="apiVersion: v2\nname: BAD_CHART\nversion: not-semver\n",
        values_yaml=(
            "replicaCount: 1\n"
            "image:\n"
            "  repository: myapp\n"
            "  tag: latest\n"
            "  pullPolicy: IfNotPresent\n"
            "resources: {}\n"
            "database:\n"
            "  password: secret123\n"
        ),
        templates={
            "deployment.yaml": (
                "apiVersion: apps/v1\n"
                "kind: Deployment\n"
                "metadata:\n"
                "  name: test\n"
                "  namespace: production\n"
                "spec:\n"
                "  template:\n"
                "    spec:\n"
                "      containers:\n"
                "        - name: app\n"
                "          securityContext:\n"
                "            privileged: true\n"
                "            runAsUser: 0\n"
                "          volumeMounts:\n"
                "            - name: host\n"
                "              mountPath: /data\n"
                "      volumes:\n"
                "        - name: host\n"
                "          hostPath:\n"
                "            path: /var/data\n"
            ),
        },
    )
