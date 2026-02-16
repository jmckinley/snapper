{{/*
Expand the name of the chart.
*/}}
{{- define "snapper.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a fully qualified app name.
*/}}
{{- define "snapper.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart label.
*/}}
{{- define "snapper.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "snapper.labels" -}}
helm.sh/chart: {{ include "snapper.chart" . }}
{{ include "snapper.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "snapper.selectorLabels" -}}
app.kubernetes.io/name: {{ include "snapper.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "snapper.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "snapper.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference.
*/}}
{{- define "snapper.image" -}}
{{- printf "%s:%s" .Values.image.repository (.Values.image.tag | default .Chart.AppVersion) }}
{{- end }}

{{/*
Database URL — from existing secret, explicit value, or constructed from bundled/external PG.
*/}}
{{- define "snapper.databaseUrl" -}}
{{- if .Values.secrets.databaseUrl }}
{{- .Values.secrets.databaseUrl }}
{{- else if .Values.postgresql.enabled }}
{{- printf "postgresql+asyncpg://%s:%s@%s-postgresql:5432/%s" .Values.postgresql.auth.username .Values.postgresql.auth.password (include "snapper.fullname" .) .Values.postgresql.auth.database }}
{{- else }}
{{- printf "postgresql+asyncpg://%s:%s@%s:%v/%s?ssl=%s" .Values.externalDatabase.username .Values.externalDatabase.password .Values.externalDatabase.host (.Values.externalDatabase.port | default 5432) .Values.externalDatabase.database (.Values.externalDatabase.sslMode | default "require") }}
{{- end }}
{{- end }}

{{/*
Redis URL — from existing secret, explicit value, or constructed from bundled/external Redis.
*/}}
{{- define "snapper.redisUrl" -}}
{{- if .Values.secrets.redisUrl }}
{{- .Values.secrets.redisUrl }}
{{- else if .Values.redis.enabled }}
{{- printf "redis://%s-redis-master:6379/0" (include "snapper.fullname" .) }}
{{- else if .Values.externalRedis.password }}
{{- printf "redis://:%s@%s:%v/%v" .Values.externalRedis.password .Values.externalRedis.host (.Values.externalRedis.port | default 6379) (.Values.externalRedis.db | default 0) }}
{{- else }}
{{- printf "redis://%s:%v/%v" .Values.externalRedis.host (.Values.externalRedis.port | default 6379) (.Values.externalRedis.db | default 0) }}
{{- end }}
{{- end }}

{{/*
Secret name to use for app credentials.
*/}}
{{- define "snapper.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "snapper.fullname" . }}
{{- end }}
{{- end }}
