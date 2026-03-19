"""Demo mode — generates a realistic sample Helm chart for showcase purposes."""
import os
import tempfile


def create_demo_chart() -> str:
    """Create a demo Helm chart with intentional issues for demonstration."""
    demo_dir = tempfile.mkdtemp(prefix="helm-doctor-demo-")
    chart_dir = os.path.join(demo_dir, "my-webapp")
    templates_dir = os.path.join(chart_dir, "templates")
    os.makedirs(templates_dir, exist_ok=True)

    # Chart.yaml — with some issues
    _write(chart_dir, "Chart.yaml", """apiVersion: v2
name: my-webapp
description: A sample web application Helm chart
version: 1.2.0
appVersion: "2.5.1"
type: application
maintainers:
  - name: DevOps Team
""")

    # values.yaml — with security and best practice issues
    _write(chart_dir, "values.yaml", """# My WebApp Configuration
replicaCount: 1

image:
  repository: myregistry/webapp
  tag: latest
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 80

ingress:
  enabled: true
  hosts:
    - host: webapp.example.com
      paths:
        - path: /
          pathType: ImplementationSpecific

resources: {}

nodeSelector: {}
tolerations: []
affinity: {}

database:
  host: db.internal
  port: 5432
  password: sup3r_s3cret_passw0rd
  username: admin
""")

    # Deployment template — with issues
    _write(templates_dir, "deployment.yaml", """apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ include "my-webapp.fullname" . }}
  namespace: production
  labels:
    app: {{ .Chart.Name }}
spec:
  replicas: {{ .Values.replicaCount }}
  selector:
    matchLabels:
      app: {{ .Chart.Name }}
  template:
    metadata:
      labels:
        app: {{ .Chart.Name }}
    spec:
      containers:
        - name: {{ .Chart.Name }}
          image: "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
          imagePullPolicy: {{ .Values.image.pullPolicy }}
          ports:
            - containerPort: 80
          env:
            - name: DB_PASSWORD
              value: {{ .Values.database.password }}
          securityContext:
            privileged: true
            runAsUser: 0
          volumeMounts:
            - name: host-data
              mountPath: /data
      volumes:
        - name: host-data
          hostPath:
            path: /var/data
""")

    # Service template
    _write(templates_dir, "service.yaml", """apiVersion: v1
kind: Service
metadata:
  name: {{ include "my-webapp.fullname" . }}
  labels:
    app.kubernetes.io/name: {{ .Chart.Name }}
    app.kubernetes.io/instance: {{ .Release.Name }}
    app.kubernetes.io/version: {{ .Chart.AppVersion }}
    app.kubernetes.io/managed-by: {{ .Release.Service }}
spec:
  type: {{ .Values.service.type }}
  ports:
    - port: {{ .Values.service.port }}
      targetPort: http
  selector:
    app: {{ .Chart.Name }}
""")

    # Ingress template
    _write(templates_dir, "ingress.yaml", """{{- if .Values.ingress.enabled -}}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ include "my-webapp.fullname" . }}
spec:
  rules:
    {{- range .Values.ingress.hosts }}
    - host: {{ .host }}
      http:
        paths:
          {{- range .paths }}
          - path: {{ .path }}
            pathType: {{ .pathType }}
            backend:
              service:
                name: {{ include "my-webapp.fullname" $ }}
                port:
                  number: 80
          {{- end }}
    {{- end }}
{{- end }}
""")

    # RBAC with overly permissive rules
    _write(templates_dir, "rbac.yaml", """apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: {{ include "my-webapp.fullname" . }}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: {{ include "my-webapp.fullname" . }}
subjects:
  - kind: ServiceAccount
    name: {{ include "my-webapp.fullname" . }}
    namespace: {{ .Release.Namespace }}
roleRef:
  kind: ClusterRole
  name: {{ include "my-webapp.fullname" . }}
  apiGroup: rbac.authorization.k8s.io
""")

    # Hook without delete policy
    _write(templates_dir, "pre-install-job.yaml", """apiVersion: batch/v1
kind: Job
metadata:
  name: {{ include "my-webapp.fullname" . }}-init
  annotations:
    "helm.sh/hook": pre-install
spec:
  template:
    spec:
      containers:
        - name: init
          image: busybox:latest
          command: ["sh", "-c", "echo Initializing..."]
      restartPolicy: Never
""")

    return chart_dir


def _write(directory: str, filename: str, content: str):
    """Write a file to the directory."""
    filepath = os.path.join(directory, filename)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content.lstrip("\n"))
