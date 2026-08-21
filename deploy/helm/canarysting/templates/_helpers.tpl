{{/*
Chart name (respecting nameOverride).
*/}}
{{- define "canarysting.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name (respecting fullnameOverride / nameOverride).
*/}}
{{- define "canarysting.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart label value (name-version).
*/}}
{{- define "canarysting.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels shared by every object.
*/}}
{{- define "canarysting.labels" -}}
helm.sh/chart: {{ include "canarysting.chart" . }}
app.kubernetes.io/name: {{ include "canarysting.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: canarysting
{{- end -}}

{{/*
Operator selector labels.
*/}}
{{- define "canarysting.operator.selectorLabels" -}}
app.kubernetes.io/name: {{ include "canarysting.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: operator
{{- end -}}

{{/*
Node-agent selector labels.
*/}}
{{- define "canarysting.nodeAgent.selectorLabels" -}}
app.kubernetes.io/name: {{ include "canarysting.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: node-agent
{{- end -}}

{{/*
Operator ServiceAccount name.
*/}}
{{- define "canarysting.operator.serviceAccountName" -}}
{{- if .Values.operator.serviceAccount.create -}}
{{- default (printf "%s-operator" (include "canarysting.fullname" .)) .Values.operator.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.operator.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Node-agent ServiceAccount name.
*/}}
{{- define "canarysting.nodeAgent.serviceAccountName" -}}
{{- if .Values.nodeAgent.serviceAccount.create -}}
{{- default (printf "%s-node-agent" (include "canarysting.fullname" .)) .Values.nodeAgent.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.nodeAgent.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Resolve the scope boundary, failing the render if it is empty. The engine and
adapter both refuse to start without a scope (never a global scope).
*/}}
{{- define "canarysting.scope" -}}
{{- required "scope.boundary is REQUIRED: CanarySting never falls back to a global scope. Set --set scope.boundary=<your-deployment>." .Values.scope.boundary -}}
{{- end -}}

{{/*
Build a fully-qualified image reference from a component's repository/tag and the
shared registry. Usage: {{ include "canarysting.image" (dict "registry" .Values.image.registry "repository" .Values.image.operator.repository "tag" .Values.image.operator.tag) }}
*/}}
{{- define "canarysting.image" -}}
{{- $registry := .registry -}}
{{- $repo := .repository -}}
{{- $tag := .tag | default "latest" -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repo $tag -}}
{{- else -}}
{{- printf "%s:%s" $repo $tag -}}
{{- end -}}
{{- end -}}
