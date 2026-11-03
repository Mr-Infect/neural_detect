package neural_detect.authz
import rego.v1
default allow := false
allow if input.principal.role == "admin"
same_tenant if input.principal.tenant_id == input.resource.tenant_id
allow if { same_tenant; input.action.category == "read"; input.principal.role in {"security_engineer","analyst","approver","auditor"} }
allow if { same_tenant; input.action.category == "approval_request"; input.principal.role in {"security_engineer","analyst","approver"} }
allow if { same_tenant; input.action.category == "approval_review"; input.principal.role == "approver" }
allow if { same_tenant; input.action.category == "detection_write"; input.principal.role == "security_engineer" }
allow if { same_tenant; input.action.category == "incident_write"; input.principal.role in {"analyst","approver"} }
allow if { same_tenant; input.action.category == "intel_write"; input.principal.role in {"security_engineer","analyst"} }
allow if { same_tenant; input.action.category == "ai_eval"; input.principal.role in {"security_engineer","auditor"} }
allow if { same_tenant; input.action.category == "telemetry_write"; input.principal.role == "admin" }
allow if { same_tenant; input.action.category == "operator_write"; input.principal.role in {"security_engineer","approver"} }
allow if { same_tenant; input.action.category == "response_execute"; input.principal.role == "admin" }
allow if { same_tenant; input.action.category == "soar"; input.principal.role in {"admin","approver"} }
