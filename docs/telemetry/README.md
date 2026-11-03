# Telemetry collection

The Compose stack accepts Beats protocol events on port 5044. Configure Filebeat, Winlogbeat, Elastic Agent, or another Beats-compatible shipper to send to this host port. The Logstash pipeline preserves the source message in event.original, adds observer provenance, and applies the matching Elasticsearch ECS ingest pipeline.

## Linux

Copy infrastructure/telemetry/filebeat.yml to the Filebeat configuration directory. Enable the linux-auth and linux-auditd inputs only where those files exist. Auditd process coverage depends on audit rules being configured on the host. Set the Zeek and Suricata inputs to enabled when their JSON logs are available. Validate the Filebeat config and restart Filebeat after editing.

## Windows

Use Winlogbeat on the Windows endpoint and copy infrastructure/telemetry/winlogbeat.yml to its configuration directory. Install and configure Sysmon separately to populate Microsoft-Windows-Sysmon/Operational. Set the Logstash host to the Ubuntu WSL machine address reachable from Windows, then validate the Winlogbeat config and restart the service.

## Registering sources

Use POST /api/v1/telemetry/sources with a name, supported kind, and dataset. Registration stores source metadata only; it does not install an endpoint agent or imply that data is arriving. The dashboard uses indexed event data and registered sources from the real services. Supported kinds are windows_sysmon, windows_eventlog, linux_auditd, linux_auth, zeek, suricata, and custom_beats.

## ECS pipelines

Run docker compose run --rm api python -m scripts.setup_elastic after Elasticsearch is ready. The setup is idempotent and installs the auth, process, network, DNS, and endpoint-alert ingest pipelines. Logstash routes Beats documents to those pipelines using ECS event.category and event.kind.
