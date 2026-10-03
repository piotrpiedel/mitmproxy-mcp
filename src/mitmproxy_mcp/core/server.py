import asyncio
import logging
import os
import shutil
import signal
import subprocess
import sys
import json
from pathlib import Path
from collections import Counter
from typing import List, Dict, Any, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, parse_qsl
import re
import re2

import structlog

from mcp.server.fastmcp import FastMCP
from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster
from curl_cffi.requests import AsyncSession
from jsonpath_ng import parse as parse_jsonpath
from bs4 import BeautifulSoup

from ..models import ScopeConfig, InterceptionRule
from .scope import ScopeManager
from .recorder import TrafficRecorder
from .interceptor import TrafficInterceptor
from .generation import normalize_scraper_flows, render_scraper_code

# Configure structlog
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.stdlib.add_log_level,
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

# Configure standard logging to output the JSON string as-is
logging.basicConfig(
    format="%(message)s",
    level=logging.INFO,
    stream=sys.stderr,
)

logger = structlog.get_logger()


class MitmController:
    def __init__(self, dump_file: Optional[str] = None):
        self.master: Optional[DumpMaster] = None
        self.proxy_task: Optional[asyncio.Task] = None
        self.scope_config = ScopeConfig()
        self.scope_manager = ScopeManager(self.scope_config)
        self.recorder = TrafficRecorder(self.scope_manager)
        self.interceptor = TrafficInterceptor()
        self.running = False
        self.port = 8080
        self.session_variables = {}
        self.dump_file = dump_file
        self.cli_upstream_proxy: Optional[str] = None
        self.browser_process: Optional[subprocess.Popen] = None
        self.browser_profile_dir: Optional[str] = None

    def _get_verify_param(self, verify_override: Optional[bool] = None) -> Any:
        if verify_override is not None:
            return verify_override

        cert_path = os.path.expanduser("~/.mitmproxy/mitmproxy-ca-cert.pem")
        if os.path.exists(cert_path):
            return cert_path

        return True

    async def start(
        self,
        port: int = 8080,
        host: str = "127.0.0.1",
        dump_file: Optional[str] = None,
        upstream_proxy: Optional[str] = None,
    ):
        if self.running:
            return "MITM is already running."

        self.port = port
        opts = options.Options(listen_host=host, listen_port=port)

        up_proxy = upstream_proxy or self.cli_upstream_proxy
        if up_proxy:
            opts.update(mode=f"upstream:{up_proxy}")
            logger.info("upstream_proxy_configured", url=up_proxy)

        self.master = DumpMaster(
            opts,
            with_termlog=False,
            with_dumper=False,
        )
        self.master.addons.add(self.recorder)
        self.master.addons.add(self.interceptor)

        save_path = dump_file or self.dump_file
        if save_path:
            opts.update(save_stream_file=save_path)
            logger.info("flow_dump_enabled", path=save_path)

        self.proxy_task = asyncio.create_task(self.master.run())
        self.running = True
        logger.info("proxy_started", host=host, port=port)
        msg = f"Started proxy on port {port}"
        if save_path:
            msg += f", dumping flows to {save_path}"
        return msg

    async def stop(self):
        if not self.running or not self.master:
            return "The proxy isn't running right now."
        # Explicitly stop all server instances to release the listening port
        # and close all active connections (keepalive connections otherwise persist)
        ps_addon = self.master.addons.get("proxyserver")
        if ps_addon:
            for handler in list(ps_addon.connections.values()):
                try:
                    for transport_io in list(handler.transports.values()):
                        if transport_io.writer and not transport_io.writer.is_closing():
                            transport_io.writer.close()
                except Exception:
                    pass
            for instance in list(ps_addon.servers._instances.values()):
                try:
                    await instance.stop()
                except Exception:
                    pass
            ps_addon.servers._instances.clear()
        self.master.shutdown()
        if self.proxy_task:
            done, _ = await asyncio.wait({self.proxy_task}, timeout=5.0)
            if not done:
                self.proxy_task.cancel()
                try:
                    await self.proxy_task
                except (asyncio.CancelledError, Exception):
                    pass
            self.proxy_task = None
        self.running = False
        logger.info("proxy_stopped")
        return "Stopped the proxy."

    async def replay_request(
        self,
        flow_id: str,
        method: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[str] = None,
        timeout: float = 30.0,
    ) -> str:
        """
        Re-executes captured request using curl_cffi
        """
        # Fetch flow details from DB (dict)
        flow_data = self.recorder.get_flow_detail(flow_id)
        if not flow_data:
            return "Couldn't find that flow"

        original_request = flow_data["request"]
        target_url = original_request["url"]
        target_method = method if method else original_request["method"]

        target_headers = dict(original_request["headers"])
        target_headers.pop("Host", None)
        target_headers.pop("Content-Length", None)
        target_headers.pop("Content-Encoding", None)

        if headers:
            target_headers.update(headers)

        target_content = None
        if body is not None:
            target_content = body
        else:
            # Prefer full body from DB; fall back to preview
            flow_obj = self.recorder.db.get_flow_object(flow_id)
            if flow_obj and flow_obj.body is not None:
                target_content = flow_obj.body
            else:
                target_content = original_request.get("body_preview")
            if not target_content:
                target_content = None

        logger.info(
            "replay_request",
            flow_id=flow_id,
            method=target_method,
            url=target_url,
            mode="stealth",
        )

        proxy_url = f"http://127.0.0.1:{self.port}"

        try:
            async with AsyncSession(
                impersonate="chrome120",
                proxies={
                    "http": proxy_url,
                    "https": proxy_url,
                },
                verify=self._get_verify_param(),
                timeout=timeout,
            ) as client:
                request_kwargs = {
                    "method": target_method,
                    "url": target_url,
                    "headers": target_headers,
                }
                if isinstance(target_content, str):
                    request_kwargs["data"] = target_content
                elif isinstance(target_content, bytes):
                    request_kwargs["data"] = target_content

                response = await client.request(**request_kwargs)

            return f"Replayed successfully! (Status: {response.status_code}). Check the traffic summary for the new flow."
        except Exception as e:
            logger.error(f"Replay failed: {e}")
            return f"That didn't work: {str(e)}"


# Global Controller Instance
controller = MitmController()

mcp = FastMCP("Mitmproxy Manager")

# --- MCP Tools ---


@mcp.tool()
async def start_proxy(
    port: int = 8080, dump_file: Optional[str] = None, upstream_proxy: Optional[str] = None
) -> str:
    """
    Start the mitmproxy instance.
    Args:
        port: Port to listen on (default 8080)
        dump_file: Optional file path to save raw mitmproxy .flow data.
            Prefix with + to append to an existing file.
        upstream_proxy: Optional upstream proxy URL (e.g., 'http://user:pass@proxy:port').
    """
    try:
        return await controller.start(
            port=port, dump_file=dump_file, upstream_proxy=upstream_proxy
        )
    except Exception as e:
        logger.error("proxy_start_failed", error=str(e))
        return f"Couldn't start the proxy: {str(e)}"


@mcp.tool()
async def stop_proxy() -> str:
    return await controller.stop()


@mcp.tool()
async def set_scope(allowed_domains: List[str]) -> str:
    controller.scope_manager.update_domains(allowed_domains)
    if allowed_domains:
        domains_str = ", ".join(allowed_domains)
    else:
        domains_str = "everything"
    return f"Updated. Now tracking: {domains_str}"


@mcp.tool()
async def set_global_header(key: str, value: str) -> str:
    rule_id = f"global_{key.lower()}"
    rule = InterceptionRule(
        id=rule_id,
        url_pattern=".*",
        resource_type="request",
        action_type="inject_header",
        key=key,
        value=value,
    )
    controller.interceptor.add_rule(rule)
    return f"Set global header: {key} = {value}"


@mcp.tool()
async def remove_global_header(key: str) -> str:
    rule_id = f"global_{key.lower()}"
    controller.interceptor.remove_rule(rule_id)
    return f"Removed global header: {key}"


@mcp.tool()
async def get_traffic_summary(limit: int = 20) -> str:
    flows = controller.recorder.get_flow_summary(limit)
    return json.dumps(flows, indent=2)


@mcp.tool()
async def inspect_flow(flow_id: str, full_body: bool = False) -> str:
    """
    Get full details of a captured flow.
    Args:
        flow_id: The ID of the captured flow
        full_body: If True, return full request body instead of 2000-char preview
    """
    logger.debug("inspect_flow", flow_id=flow_id)
    data = controller.recorder.get_flow_detail(flow_id)
    if not data:
        return "Couldn't find that flow."
    if full_body and data.get("request"):
        flow_obj = controller.recorder.db.get_flow_object(flow_id)
        if flow_obj and flow_obj.body is not None:
            data["request"]["body"] = flow_obj.body
            data["request"].pop("body_preview", None)
    return json.dumps(data, indent=2)


@mcp.tool()
async def inspect_flows(
    flow_ids: str,
    fields: str = None,
    full_body: bool = False,
) -> str:
    """
    Batch inspect multiple flows in one call. Reduces context usage vs
    calling inspect_flow N times.
    Args:
        flow_ids: Comma-separated list of flow IDs to inspect
        fields: Comma-separated list of DB columns to select.
            e.g. "id,url,method,request_headers,request_body" to skip
            response data. Default: all columns.
        full_body: If True, return full request body instead of preview
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    columns = [c.strip() for c in fields.split(",")] if fields else None
    derived_fields = set()
    if columns:
        derived_fields = {c for c in columns if c in {"content_type", "response_content_type"}}
        if derived_fields:
            if "response_headers" not in columns:
                columns.append("response_headers")
            # Remove derived field names before passing to DB query
            columns = [c for c in columns if c not in derived_fields]
    # Always include id in columns
    if columns and "id" not in columns:
        columns.insert(0, "id")

    results = controller.recorder.db.get_by_ids(
        ids, columns=columns, ordered_headers=True
    )

    if derived_fields:
        for entry in results:
            headers = entry.get("response", {}).get("headers") or []
            header_dict = {k.lower(): v for k, v in headers}
            content_type = header_dict.get("content-type", "unknown")
            if "content_type" in derived_fields:
                entry["content_type"] = content_type
            if "response_content_type" in derived_fields:
                entry["response_content_type"] = content_type

    if full_body and not columns:
        # Replace truncated previews with full bodies
        for entry in results:
            req = entry.get("request")
            if req:
                flow_obj = controller.recorder.db.get_flow_object(entry["id"])
                if flow_obj and flow_obj.body is not None:
                    req["body"] = flow_obj.body

    return json.dumps(results, indent=2)


def _json_type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int) and not isinstance(value, bool):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if isinstance(value, list):
        return "list"
    if isinstance(value, dict):
        return "dict"
    if value is None:
        return "null"
    return type(value).__name__


@mcp.tool()
async def get_flow_schema(flow_id: str) -> str:
    """Infer a simple top-level schema from a flow's JSON response body.
    For deeper schema with nesting, use infer_response_schema instead."""
    body_content = controller.recorder.db.get_response_body(flow_id)
    if body_content is None:
        return "Flow not found."
    if not body_content:
        return "Flow has no response body."

    try:
        data = json.loads(body_content)
    except json.JSONDecodeError:
        return "Response body is not valid JSON."

    if isinstance(data, list):
        if data and isinstance(data[0], dict):
            schema = {"type": "array", "length": len(data), "item_keys": {key: _json_type_name(value) for key, value in data[0].items()}}
        else:
            schema = {"type": "array", "length": len(data)}
        return json.dumps(schema, indent=2)

    if not isinstance(data, dict):
        return f"Response is JSON but not an object (it's {type(data).__name__})."

    schema = {key: _json_type_name(value) for key, value in data.items()}
    return json.dumps(schema, indent=2)


@mcp.tool()
async def load_traffic_file(
    file_path: str,
    append: bool = False,
    scope: str = None,
) -> str:
    """
    Import flows from a HAR or mitmproxy flow file into the traffic database.
    After import, all traffic inspection tools work on the imported data.
    No proxy needs to be running.
    Args:
        file_path: Path to .har or .mitm/.flow file
        append: If True, keep existing traffic. If False (default), clear first.
        scope: Comma-separated list of domains to filter by during import.
            Only flows matching these domains are imported.
    """
    scope_list = (
        [d.strip() for d in scope.split(",") if d.strip()] if scope else None
    )

    # Security: Prevent path traversal and restrict to working directory
    try:
        requested_path = Path(file_path).resolve()
        base_dir = Path.cwd().resolve()
        if not str(requested_path).startswith(str(base_dir)):
            return json.dumps({
                "status": "error",
                "message": f"Security Error: Access denied to {file_path}. Path must be within the project directory."
            })
    except Exception as e:
        return json.dumps({"status": "error", "message": f"Invalid path: {str(e)}"})

    try:
        stats = await asyncio.to_thread(
            controller.recorder.db.import_from_file,
            str(requested_path), append=append, scope=scope_list
        )
        return json.dumps(
            {
                "status": "ok",
                "imported": stats["imported"],
                "skipped": stats["skipped"],
                "errors": stats["errors"],
            }
        )
    except Exception as e:
        return json.dumps({"status": "error", "message": str(e)})


@mcp.tool()
async def extract_from_flow(flow_id: str, json_path: str = None, css_selector: str = None) -> str:
    """
    Extract specific data from a flow's response body using JSONPath or CSS
    selectors.
    Args:
        flow_id: The ID of the captured flow
        json_path: A JSONPath expression to extract data from a JSON response
        css_selector: A CSS selector to extract data from an HTML/XML response
    """
    body_content = controller.recorder.db.get_response_body(flow_id)
    if body_content is None:
        return "No matching flow."
    if not body_content:
        return "Flow has no response body."

    if json_path:
        try:
            data = json.loads(body_content)
            jsonpath_expr = parse_jsonpath(json_path)
            matches = [match.value for match in jsonpath_expr.find(data)]
            return json.dumps(matches, indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return "Response body is not valid JSON."
        except Exception as e:
            return f"Error executing JSONPath: {str(e)}"

    if css_selector:
        try:
            soup = BeautifulSoup(body_content, "html.parser")
            elements = soup.select(css_selector)

            result = []
            for el in elements:
                result.append({"text": el.get_text(strip=True), "html": str(el), "attrs": el.attrs})

            return json.dumps(result, indent=2, ensure_ascii=False)
        except Exception as e:
            return f"Error executing CSS Selector: {str(e)}"

    return "You must provide a json_path or a css_selector."


@mcp.tool()
async def search_traffic(
    query: str = None,
    domain: str = None,
    method: str = None,
    limit: int = 50,
) -> str:
    """
    Search captured traffic using filters.
    Args:
        query: Keywords to search in URL or body
        domain: Filter by domain name
        method: Filter by HTTP method (GET, POST, etc.)
        limit: Max results to return
    """
    results = controller.recorder.search(query, domain, method, limit)
    return json.dumps(results, indent=2)


@mcp.tool()
async def set_session_variable(name: str, value: str) -> str:
    """Manually set a session variable to use in replayed flows."""
    controller.session_variables[name] = value
    return f"Set session variable ${name} = {value}"


@mcp.tool()
async def extract_session_variable(
    name: str, flow_id: str, regex_pattern: str, group_index: int = 1
) -> str:
    """
    Extract a value from a flow's response body using a regex and store it as a session variable.
    Args:
        name: Variable name (referenced as $name in replay_flow)
        flow_id: The ID of the flow to extract from
        regex_pattern: The regex pattern with capture groups
        group_index: Which regex capture group to extract (default: 1)
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "No matching flow."

    response = flow_data.get("response")
    body_content = response.get("body_preview") if response else None
    if not body_content:
        return "Flow has no response body."
    try:
        match = re2.search(regex_pattern, body_content)
        if match:
            value = match.group(group_index)
            controller.session_variables[name] = value
            return f"Extracted and set ${name} = {value}"
        else:
            return f"Pattern not found in response body."
    except Exception as e:
        return f"Error applying regex: {str(e)}"


def _resolve_template(template_str: str, variables: dict) -> str:
    """Resolves $variable placeholders in a string."""
    result = template_str
    for k, v in variables.items():
        result = result.replace(f"${k}", str(v))
    return result


@mcp.tool()
async def clear_traffic() -> str:
    """Clear all captured traffic from the database."""
    controller.recorder.clear()
    return "Cleared all traffic history."


@mcp.tool()
async def fuzz_endpoint(
    flow_id: str,
    target_param: str,
    param_type: str,
    payload_category: str,
    timeout: float = 10.0,
) -> str:
    """
    Fuzz an endpoint by substituting a target parameter with a category of
    DAST payloads.
    Args:
        flow_id: The flow to replay as the base request.
        target_param: The name of the parameter to replace.
        param_type: The location of the parameter: 'query' or 'json_body'.
        payload_category: The category of payloads
        ('sqli', 'xss', 'path_traversal').
    """
    flow_data = controller.recorder.get_flow_detail(flow_id)
    if not flow_data:
        return "No matching flow."

    if payload_category == "sqli":
        payloads = [
            "'",
            '"',
            "' OR '1'='1",
            "'; DROP TABLE users--",
            "1' ORDER BY 1--+",
        ]
    elif payload_category == "xss":
        payloads = [
            "<script>alert(1)</script>",
            '"><script>alert(1)</script>',
            "<img src=x onerror=alert(1)>",
        ]
    elif payload_category == "path_traversal":
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/windows/win.ini",
        ]
    else:
        return "Unknown payload category. Use 'sqli', 'xss', or 'path_traversal'."

    original_request = flow_data["request"]
    base_url = original_request["url"]
    method = original_request["method"]

    target_headers = dict(original_request["headers"])
    target_headers.pop("Host", None)
    target_headers.pop("Content-Length", None)
    target_headers.pop("Content-Encoding", None)

    # Get baseline response for anomaly detection
    try:
        baseline_flow = controller.recorder.db.get_flow_object(flow_id)
        if baseline_flow and baseline_flow.response:
            baseline_status = baseline_flow.response.status_code
        else:
            baseline_status = 200

        if baseline_flow and baseline_flow.response and baseline_flow.response.content:
            baseline_len = len(baseline_flow.response.content)
        else:
            baseline_len = 0
    except Exception:
        baseline_status = 200
        baseline_len = 0

    proxy_url = f"http://127.0.0.1:{controller.port}"
    anomalies = []

    async with AsyncSession(
        impersonate="chrome120",
        proxies={"http": proxy_url, "https": proxy_url},
        verify=controller._get_verify_param(),
        timeout=timeout,
    ) as client:
        tasks = []
        for payload in payloads:
            req_url = base_url
            req_body = None

            if param_type == "query":
                parsed_url = urlparse(base_url)
                qs = parse_qsl(parsed_url.query)
                new_qs = [(k, payload if k == target_param else v) for k, v in qs]
                # If param didn't exist, add it
                if target_param not in [k for k, v in qs]:
                    new_qs.append((target_param, payload))

                req_url = parsed_url._replace(query=urlencode(new_qs)).geturl()

                if original_request.get("body_preview"):
                    flow_obj = controller.recorder.db.get_flow_object(flow_id)
                    req_body = flow_obj.body
                    if not req_body:
                        req_body = original_request.get("body_preview")

            elif param_type == "json_body":
                flow_obj = controller.recorder.db.get_flow_object(flow_id)
                body_content = flow_obj.body
                if not body_content:
                    body_content = original_request.get("body_preview", "")

                try:
                    if isinstance(body_content, bytes):
                        body_content = body_content.decode("utf-8")
                    body_data = json.loads(body_content)
                    if target_param in body_data:
                        body_data[target_param] = payload
                    else:
                        # Simple nested replacement naive approach could be added here
                        body_data[target_param] = payload
                    req_body = json.dumps(body_data)
                except Exception as e:
                    return f"Failed to parse or modify JSON body: {str(e)}"
            else:
                return "Unknown param_type. Use 'query' or 'json_body'."

            # Coroutine for the request
            async def run_req(p=payload, u=req_url, b=req_body):
                try:
                    request_kwargs = {
                        "method": method,
                        "url": u,
                        "headers": target_headers,
                    }
                    if b is not None:
                        request_kwargs["data"] = b

                    resp = await client.request(**request_kwargs)

                    status = resp.status_code
                    content_len = len(resp.content) if resp.content else 0

                    # Anomaly detection heuristics
                    if status >= 500:
                        return {
                            "payload": p,
                            "anomaly": "Server Error (5xx)",
                            "status": status,
                        }
                    if status != baseline_status:
                        return {
                            "payload": p,
                            "anomaly": (f"Status Code Deviation ({baseline_status} -> {status})"),
                            "status": status,
                        }

                    # Length deviation by > 20%
                    if baseline_len > 0:
                        diff_ratio = abs(content_len - baseline_len) / baseline_len
                        if diff_ratio > 0.2:
                            return {
                                "payload": p,
                                "anomaly": "Content Length Deviation (>20%)",
                                "status": status,
                                "len": content_len,
                            }
                    return None
                except Exception as e:
                    return {
                        "payload": p,
                        "anomaly": f"Request Failed: {str(e)}",
                    }

            tasks.append(run_req())

        # Run concurrently
        results = await asyncio.gather(*tasks)
        for r in results:
            if r:
                anomalies.append(r)

    if not anomalies:
        return "Fuzzing complete, No significant anomalies detected."

    return json.dumps(
        {
            "baseline_status": baseline_status,
            "baseline_len": baseline_len,
            "anomalies": anomalies,
        },
        indent=2,
    )


@mcp.tool()
async def replay_flow(
    flow_id: str,
    method: str = None,
    headers_json: str = None,
    body: str = None,
    timeout: float = 30.0,
) -> str:
    """
    Replay a captured flow, optionally with modified method, headers, or body.
    Supports session variable injection (e.g., $token) in headers and body.
    """

    # Resolve templates in headers and body if we have variables
    resolved_headers_json = headers_json
    resolved_body = body

    # Treat the sentinel value "__omit__" as no body
    if resolved_body == "__omit__":
        resolved_body = None

    if controller.session_variables:
        if resolved_headers_json:
            resolved_headers_json = _resolve_template(
                resolved_headers_json, controller.session_variables
            )
        if resolved_body:
            resolved_body = _resolve_template(resolved_body, controller.session_variables)

    parsed_headers = None
    if resolved_headers_json:
        try:
            parsed_headers = json.loads(resolved_headers_json)
        except json.JSONDecodeError:
            return "The headers_json parameter needs to be valid JSON."

    return await controller.replay_request(
        flow_id,
        method,
        parsed_headers,
        resolved_body,
        timeout,
    )


@mcp.tool()
async def add_interception_rule(
    rule_id: str,
    action_type: str,
    url_pattern: str = ".*",
    method: str = None,
    key: str = None,
    value: str = None,
    search_pattern: str = None,
    phase: str = "request",
) -> str:
    if phase not in ["request", "response"]:
        return "Phase needs to be either 'request' or 'response'"

    try:
        rule = InterceptionRule(
            id=rule_id,
            url_pattern=url_pattern,
            method=method,
            resource_type=phase,  # type: ignore
            action_type=action_type,  # type: ignore
            key=key,
            value=value,
            search_pattern=search_pattern,
        )
    except Exception as e:
        return f"Invalid rule parameters: {str(e)}"

    if not controller.interceptor.add_rule(rule):
        return f"Invalid or unsupported regex for rule '{rule_id}'"
    return f"Added rule '{rule_id}'"


@mcp.tool()
async def list_rules() -> str:
    rules_dict = {
        rid: {
            "action": r.action_type,
            "url_pattern": r.url_pattern,
            "phase": r.resource_type,
        }
        for rid, r in controller.interceptor.rules.items()
    }
    return json.dumps(rules_dict, indent=2)


@mcp.tool()
async def clear_rules() -> str:
    controller.interceptor.clear_rules()
    return "Cleared all interception rules."


@mcp.tool()
async def list_tools() -> str:
    """List all available tools with their descriptions."""
    tools = await mcp.list_tools()
    tool_list = []
    for tool in tools:
        tool_list.append(
            {"name": tool.name, "description": tool.description, "input_schema": tool.inputSchema}
        )
    return json.dumps(tool_list, indent=2)


# --- API Analysis Tools (Updated for Dicts) ---


def _normalize_path(path: str) -> Tuple[str, List[str]]:
    segments = path.split("/")
    normalized = []
    params = []

    for seg in segments:
        if not seg:
            normalized.append("")
            continue
        if re.match(r"^\d+$", seg):
            normalized.append("{id}")
            params.append("id")
        elif re.match(
            r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-"
            r"[0-9a-f]{12}$",
            seg,
            re.I,
        ):
            normalized.append("{uuid}")
            params.append("uuid")
        elif re.match(r"^[0-9a-f]{24}$", seg, re.I):
            normalized.append("{objectId}")
            params.append("objectId")
        elif len(seg) > 20 and re.match(r"^[a-zA-Z0-9_-]+$", seg):
            normalized.append("{token}")
            params.append("token")
        else:
            normalized.append(seg)

    return "/".join(normalized), params


def _detect_content_type(headers: Dict[str, Any]) -> str:
    ct = headers.get("content-type", headers.get("Content-Type", ""))
    if "json" in ct.lower():
        return "json"
    elif "form" in ct.lower():
        return "form"
    elif "xml" in ct.lower():
        return "xml"
    elif "text" in ct.lower():
        return "text"
    return "unknown"


def _generate_openapi_spec(
    clusters: List[Dict[str, Any]],
    title: str = "Reconstructed API",
    version: str = "1.0.0",
) -> Dict[str, Any]:
    """Reconstructs an OpenAPI v3 spec from API clusters."""
    spec = {
        "openapi": "3.0.0",
        "info": {"title": title, "version": version},
        "paths": {},
    }

    for cluster in clusters:
        path = cluster["path_pattern"]
        # OpenAPI paths must start with /
        if not path.startswith("/"):
            path = "/" + path

        method = cluster["method"].lower()

        if path not in spec["paths"]:
            spec["paths"][path] = {}

        operation = {
            "summary": f"{method.upper()} {path}",
            "parameters": [],
            "responses": {},
        }

        # Add path params
        for param in cluster["path_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "path",
                    "required": True,
                    "schema": {"type": "string"},
                }
            )

        # Add query params
        for param in cluster["query_params"]:
            operation["parameters"].append(
                {
                    "name": param,
                    "in": "query",
                    # We could guess type here, default to string
                    "schema": {"type": "string"},
                }
            )

        # Add headers as parameters if significant
        # (simplified, ignoring common browser headers already handled)

        # Responses
        for status_code, count in cluster["status_codes"].items():
            content_types = cluster["content_types"]
            # Default response description
            desc = f"Response with status {status_code}"

            resp_obj = {"description": desc}

            if content_types:
                resp_obj["content"] = {}
                for ct in content_types:
                    if ct == "json":
                        media_type = "application/json"
                    elif ct == "xml":
                        media_type = "application/xml"
                    elif ct == "form":
                        media_type = "application/x-www-form-urlencoded"
                    else:
                        media_type = "text/plain"

                    # Could be populated with inferred schema
                    resp_obj["content"][media_type] = {"schema": {"type": "object"}}

            operation["responses"][str(status_code)] = resp_obj

        spec["paths"][path][method] = operation

    return spec


@mcp.tool()
async def export_openapi_spec(domain: str = None, limit: int = None) -> str:
    """
    Exports captured API traffic patterns to an OpenAPI v3 JSON specification.
    Args:
        domain: Filter traffic by domain
        limit: Max number of traffic flows to analyze. None = all flows.
    """
    patterns_json = await get_api_patterns(domain, limit)
    clusters = json.loads(patterns_json)

    spec = _generate_openapi_spec(
        clusters,
        title=f"Reconstructed API - {domain if domain else 'All'}",
    )
    return json.dumps(spec, indent=2)


@mcp.tool()
async def get_api_patterns(domain: str = None, limit: int = None) -> str:
    """
    Cluster captured traffic into endpoint patterns.
    Args:
        domain: Filter traffic by domain
        limit: Max number of flows to analyze. None = all flows.
    """
    flows = controller.recorder.get_all_for_analysis(lightweight=True)

    if domain:
        flows = [f for f in flows if domain in f["request"]["url"]]

    if limit is not None:
        flows = flows[:limit]

    endpoint_clusters: Dict[str, Dict[str, Any]] = {}

    for f in flows:
        parsed = urlparse(f["request"]["url"])
        normalized_path, path_params = _normalize_path(parsed.path)
        method = f["request"]["method"]
        key = f"{method} {normalized_path}"

        if key not in endpoint_clusters:
            endpoint_clusters[key] = {
                "method": method,
                "path_pattern": normalized_path,
                "path_params": path_params,
                "query_params": set(),
                "request_headers": Counter(),
                "response_status_codes": Counter(),
                "content_types": Counter(),
                "sample_flow_ids": [],
                "count": 0,
            }

        cluster = endpoint_clusters[key]
        cluster["count"] += 1
        cluster["sample_flow_ids"].append(f["id"])

        query_params = parse_qs(parsed.query)
        for param in query_params.keys():
            cluster["query_params"].add(param)

        skip_headers = {
            "host",
            "user-agent",
            "accept",
            "accept-encoding",
            "accept-language",
            "connection",
            "content-length",
            "content-type",
        }
        for h in f["request"]["headers"]:
            if h.lower() not in skip_headers:
                cluster["request_headers"][h] += 1

        if f["response"]:
            ct_key = _detect_content_type(f["response"]["headers"])
            cluster["response_status_codes"][f["response"]["status_code"]] += 1
            cluster["content_types"][ct_key] += 1

    result = []
    for key, cluster in sorted(endpoint_clusters.items(), key=lambda x: -x[1]["count"]):
        result.append(
            {
                "endpoint": key,
                "method": cluster["method"],
                "path_pattern": cluster["path_pattern"],
                "path_params": cluster["path_params"],
                "query_params": list(cluster["query_params"]),
                "common_headers": dict(cluster["request_headers"].most_common(10)),
                "status_codes": dict(cluster["response_status_codes"]),
                "content_types": dict(cluster["content_types"]),
                "request_count": cluster["count"],
                "sample_flow_ids": cluster["sample_flow_ids"][:3],
            }
        )

    return json.dumps(result, indent=2)


@mcp.tool()
async def detect_auth_pattern(flow_ids: str = None) -> str:
    if flow_ids:
        target_ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
        flows = controller.recorder.get_by_ids(target_ids)
    else:
        flows = controller.recorder.get_all_for_analysis()

    auth_signals = {
        "oauth2": {"detected": False, "signals": [], "flows": []},
        "jwt": {"detected": False, "signals": [], "flows": []},
        "api_key": {"detected": False, "signals": [], "flows": []},
        "session_cookie": {"detected": False, "signals": [], "flows": []},
        "csrf": {"detected": False, "signals": [], "flows": []},
        "basic_auth": {"detected": False, "signals": [], "flows": []},
        "bearer_token": {"detected": False, "signals": [], "flows": []},
    }

    for f in flows:
        headers = f["request"]["headers"]
        path = urlparse(f["request"]["url"]).path.lower()

        auth_header = headers.get(
            "Authorization",
            headers.get("authorization", ""),
        )

        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            auth_signals["bearer_token"]["detected"] = True
            auth_signals["bearer_token"]["flows"].append(f["id"])
            if token.count(".") == 2:
                auth_signals["jwt"]["detected"] = True
                auth_signals["jwt"]["signals"].append("Bearer token appears to be JWT format")
                auth_signals["jwt"]["flows"].append(f["id"])

        if auth_header.startswith("Basic "):
            auth_signals["basic_auth"]["detected"] = True
            auth_signals["basic_auth"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(k in h_lower for k in ["x-api-key", "api-key", "apikey", "x-auth-token"]):
                auth_signals["api_key"]["detected"] = True
                auth_signals["api_key"]["signals"].append(f"Header: {h}")
                auth_signals["api_key"]["flows"].append(f["id"])

        if any(p in path for p in ["/oauth", "/token", "/authorize", "/auth/callback"]):
            auth_signals["oauth2"]["detected"] = True
            auth_signals["oauth2"]["signals"].append(f"OAuth endpoint: {path}")
            auth_signals["oauth2"]["flows"].append(f["id"])

        body_text = f["request"].get("body")
        if body_text:
            if any(
                p in body_text.lower()
                for p in [
                    "grant_type=",
                    "refresh_token=",
                    "client_id=",
                ]
            ):
                auth_signals["oauth2"]["detected"] = True
                auth_signals["oauth2"]["signals"].append("OAuth2 parameters in request body")
                auth_signals["oauth2"]["flows"].append(f["id"])

        cookie_header = headers.get("Cookie", headers.get("cookie", ""))
        if cookie_header:
            cookies = cookie_header.split(";")
            for cookie in cookies:
                c_name = cookie.strip().split("=")[0].lower() if "=" in cookie else ""
                if any(s in c_name for s in ["session", "sid", "sess", "auth"]):
                    auth_signals["session_cookie"]["detected"] = True
                    auth_signals["session_cookie"]["signals"].append(f"Session cookie: {c_name}")
                    auth_signals["session_cookie"]["flows"].append(f["id"])

        for h, v in headers.items():
            h_lower = h.lower()
            if any(c in h_lower for c in ["csrf", "xsrf", "x-csrf", "x-xsrf"]):
                auth_signals["csrf"]["detected"] = True
                auth_signals["csrf"]["signals"].append(f"CSRF header: {h}")
                auth_signals["csrf"]["flows"].append(f["id"])

    for key in auth_signals:
        auth_signals[key]["flows"] = list(set(auth_signals[key]["flows"]))[:5]
        auth_signals[key]["signals"] = list(set(auth_signals[key]["signals"]))

    detected = [k for k, v in auth_signals.items() if v["detected"]]

    return json.dumps(
        {
            "detected_auth_types": detected,
            "details": auth_signals,
        },
        indent=2,
    )


@mcp.tool()
async def generate_scraper_code(flow_ids: str, target_framework: str = "curl_cffi") -> str:
    """
    Generate executable scraper/automation code from a comma-separated list of
    flow IDs.
    Args:
        flow_ids: Comma-separated list of flow IDs to include in the script.
        target_framework: The framework to generate code for.
    """
    ids = [fid.strip() for fid in flow_ids.split(",") if fid.strip()]
    flows_data = []

    for fid in ids:
        data = controller.recorder.get_flow_detail(fid)
        if data:
            flows_data.append(data)

    if not flows_data:
        return "No valid flows found for the provided IDs."

    normalized_flows = normalize_scraper_flows(flows_data, controller.recorder)
    return render_scraper_code(target_framework, normalized_flows)


_CHROME_SEARCH_PATHS = [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/opt/google/chrome/chrome",
    "/usr/bin/chromium-browser",
    "/usr/bin/chromium",
    "/snap/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def _find_chrome() -> Optional[str]:
    for path in _CHROME_SEARCH_PATHS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return shutil.which("google-chrome") or shutil.which("chromium")


@mcp.tool()
async def launch_chrome_with_proxy(
    url: str = "",
    profile: str = "",
    ignore_cert_errors: bool = True,
) -> str:
    """
    Launch the system's real Chrome/Chromium browser with traffic routed through mitmproxy.
    Opens a visible browser window — you (or the user) interact with it normally,
    and all HTTP/HTTPS traffic is captured for analysis.
    Starts the proxy automatically if it is not already running.
    Call close_browser() when done.

    Args:
        url: URL to open on launch (empty = blank tab)
        profile: Custom Chrome profile directory (default: ~/.chrome-mitm-profile)
        ignore_cert_errors: Skip TLS cert verification for mitmproxy CA (default True)
    """
    if controller.browser_process and controller.browser_process.poll() is None:
        return json.dumps({"error": "Browser already running. Call close_browser() first."})

    chrome_path = _find_chrome()
    if not chrome_path:
        return json.dumps({"error": "Chrome/Chromium not found. Install Google Chrome."})

    if not controller.running:
        await controller.start()
        logger.info("launch_chrome_autostarted_proxy")

    profile_dir = profile or os.path.expanduser("~/.chrome-mitm-profile")
    controller.browser_profile_dir = profile_dir

    cmd = [
        chrome_path,
        f"--proxy-server=http://127.0.0.1:{controller.port}",
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        "--start-maximized",
        "--disable-background-timer-throttling",
        "--disable-renderer-backgrounding",
        "--disable-backgrounding-occluded-windows",
    ]
    if ignore_cert_errors:
        cmd.append("--ignore-certificate-errors")
    if url:
        cmd.append(url)

    controller.browser_process = subprocess.Popen(
        cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    logger.info("chrome_launched", pid=controller.browser_process.pid, profile=profile_dir)

    return json.dumps(
        {
            "chrome": chrome_path,
            "pid": controller.browser_process.pid,
            "proxy": f"http://127.0.0.1:{controller.port}",
            "profile": profile_dir,
            "message": "Chrome launched with proxy. Browse normally — all traffic is captured. Call close_browser() when done.",
        },
        indent=2,
    )


@mcp.tool()
async def close_browser() -> str:
    """
    Close the Chrome browser that was launched by launch_chrome_with_proxy.
    """
    proc = controller.browser_process
    if not proc:
        return "No browser was launched by this session."
    if proc.poll() is not None:
        controller.browser_process = None
        return "Browser already closed."

    try:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
    except Exception as e:
        return f"Error closing browser: {e}"

    controller.browser_process = None
    logger.info("chrome_closed")
    return "Browser closed."


@mcp.tool()
async def browse_with_proxy(
    url: str,
    wait_for: str = "networkidle",
    timeout_ms: int = 15000,
    headless: bool = True,
    extra_wait_ms: int = 3000,
) -> str:
    """
    Open a URL in a Playwright Chromium browser routed through the mitmproxy proxy.
    All HTTP/HTTPS traffic is captured and available via get_traffic_summary / get_api_patterns.
    Starts the proxy automatically if it is not already running.
    Requires Playwright browsers: run 'playwright install chromium' once before first use.

    Args:
        url: URL to open
        wait_for: Navigation end condition — 'networkidle', 'load', or 'domcontentloaded'
        timeout_ms: Navigation timeout in milliseconds (default 15000)
        headless: Run the browser without a visible window (default True)
        extra_wait_ms: Additional wait after page load for JS-triggered fetches (default 3000)
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return "playwright is not installed. Run: playwright install chromium"

    if not controller.running:
        result = await controller.start()
        logger.info("browse_with_proxy_autostarted_proxy", result=result)

    proxy_url = f"http://127.0.0.1:{controller.port}"

    def _count_flows() -> int:
        with controller.recorder.db._get_conn() as conn:
            return conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]

    before = _count_flows()
    domain = urlparse(url).netloc

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=headless,
                proxy={"server": proxy_url},
                args=["--ignore-certificate-errors"],
            )
            context = await browser.new_context(ignore_https_errors=True)
            page = await context.new_page()
            try:
                await page.goto(url, wait_until=wait_for, timeout=timeout_ms)
            except Exception:
                # networkidle timeout is normal for SPAs with polling — not a hard failure
                pass
            if extra_wait_ms > 0:
                await asyncio.sleep(extra_wait_ms / 1000)
            await browser.close()
    except Exception as e:
        err = str(e)
        if "Executable doesn't exist" in err or "playwright install" in err.lower():
            return "Playwright browser binaries not found. Run: playwright install chromium"
        return f"Browser error: {err}"

    after = _count_flows()

    return json.dumps(
        {
            "url": url,
            "proxy": proxy_url,
            "flows_captured": after - before,
            "next_steps": [
                f"get_api_patterns(domain='{domain}')",
                "get_traffic_summary(limit=20)",
                f"export_openapi_spec(domain='{domain}')",
                f"generate_scraper_code(flow_ids='...')",
            ],
        },
        indent=2,
    )


@mcp.tool()
async def get_response_body(
    flow_id: str,
    json_path: str = "",
    max_chars: int = 50000,
) -> str:
    """
    Get the full response body of a captured flow, optionally filtered by JSONPath.
    Unlike inspect_flow (2000 char preview), this returns the complete response.
    Args:
        flow_id: The ID of the captured flow
        json_path: Optional JSONPath expression to extract specific data (e.g. '$.listings[0]', '$.cities[*].name')
        max_chars: Maximum characters to return (default 50000). Use 0 for unlimited.
    """
    body = controller.recorder.db.get_response_body(flow_id)
    if body is None:
        return "Flow not found."
    if not body:
        return "Flow has no response body."

    if json_path:
        try:
            data = json.loads(body)
            expr = parse_jsonpath(json_path)
            matches = [m.value for m in expr.find(data)]
            if not matches:
                return f"No matches for JSONPath: {json_path}"
            body = json.dumps(matches if len(matches) > 1 else matches[0], indent=2, ensure_ascii=False)
        except json.JSONDecodeError:
            return "Response body is not valid JSON."
        except Exception as e:
            return f"JSONPath error: {e}"

    if max_chars and len(body) > max_chars:
        return body[:max_chars] + f"\n\n... [TRUNCATED at {max_chars} chars, total {len(body)}]"
    return body


@mcp.tool()
async def get_api_summary(
    domain: str = "",
    content_type: str = "json",
    min_calls: int = 1,
) -> str:
    """
    Compact API endpoint summary — one line per endpoint, no headers, no flow IDs.
    Designed for quick overview without flooding context.
    Args:
        domain: Filter by domain (e.g. 'rynkoradar.pl')
        content_type: Filter by response content type: 'json', 'html', 'text', or 'all' (default: 'json')
        min_calls: Only show endpoints with at least this many calls (default: 1)
    """
    flows = controller.recorder.get_all_for_analysis(lightweight=True)

    if domain:
        flows = [f for f in flows if domain in f["request"]["url"]]

    clusters: Dict[str, Dict[str, Any]] = {}
    for f in flows:
        parsed = urlparse(f["request"]["url"])
        normalized_path, _ = _normalize_path(parsed.path)
        method = f["request"]["method"]
        key = f"{method} {normalized_path}"

        if key not in clusters:
            clusters[key] = {
                "query_params": set(),
                "status_codes": Counter(),
                "content_types": Counter(),
                "count": 0,
                "sample_urls": [],
                "response_sizes": [],
            }

        c = clusters[key]
        c["count"] += 1
        for param in parse_qs(parsed.query).keys():
            c["query_params"].add(param)
        if len(c["sample_urls"]) < 2:
            c["sample_urls"].append(f["request"]["url"])

        if f["response"]:
            ct = _detect_content_type(f["response"]["headers"])
            c["status_codes"][f["response"]["status_code"]] += 1
            c["content_types"][ct] += 1

    lines = []
    for key, c in sorted(clusters.items(), key=lambda x: -x[1]["count"]):
        if c["count"] < min_calls:
            continue
        dominant_ct = c["content_types"].most_common(1)[0][0] if c["content_types"] else "unknown"
        if content_type != "all" and dominant_ct != content_type:
            continue

        statuses = ",".join(str(s) for s in sorted(c["status_codes"].keys()))
        params = ", ".join(sorted(c["query_params"])) if c["query_params"] else "-"
        lines.append(f"{key}  x{c['count']}  [{statuses}]  params: {params}")
        for url in c["sample_urls"][:1]:
            lines.append(f"    example: {url}")

    if not lines:
        return f"No API endpoints found matching filters (domain={domain!r}, content_type={content_type!r}, min_calls={min_calls})"

    header = f"API endpoints ({len(lines) // 2} unique) for domain={domain or 'all'}"
    return header + "\n" + "\n".join(lines)


@mcp.tool()
async def diff_responses(
    flow_id_a: str,
    flow_id_b: str,
    json_path: str = "",
) -> str:
    """
    Compare response bodies of two flows. Shows structural differences for JSON responses.
    Args:
        flow_id_a: First flow ID
        flow_id_b: Second flow ID
        json_path: Optional JSONPath to compare a specific subtree
    """
    body_a = controller.recorder.db.get_response_body(flow_id_a)
    body_b = controller.recorder.db.get_response_body(flow_id_b)

    if body_a is None:
        return f"Flow {flow_id_a} not found."
    if body_b is None:
        return f"Flow {flow_id_b} not found."

    def _extract(body: str, path: str):
        if not path:
            return body
        data = json.loads(body)
        expr = parse_jsonpath(path)
        matches = [m.value for m in expr.find(data)]
        return matches[0] if len(matches) == 1 else matches

    try:
        val_a = _extract(body_a, json_path)
        val_b = _extract(body_b, json_path)
    except json.JSONDecodeError:
        return "One or both response bodies are not valid JSON."
    except Exception as e:
        return f"Extraction error: {e}"

    def _schema_diff(a, b, path="$"):
        diffs = []
        if type(a) != type(b):
            diffs.append(f"{path}: type {type(a).__name__} vs {type(b).__name__}")
            return diffs
        if isinstance(a, dict):
            keys_a, keys_b = set(a.keys()), set(b.keys())
            for k in keys_a - keys_b:
                diffs.append(f"{path}.{k}: only in A")
            for k in keys_b - keys_a:
                diffs.append(f"{path}.{k}: only in B")
            for k in keys_a & keys_b:
                diffs.extend(_schema_diff(a[k], b[k], f"{path}.{k}"))
        elif isinstance(a, list):
            diffs.append(f"{path}: array len {len(a)} vs {len(b)}")
            if a and b:
                diffs.extend(_schema_diff(a[0], b[0], f"{path}[0]"))
        elif a != b:
            sa, sb = str(a)[:80], str(b)[:80]
            diffs.append(f"{path}: {sa!r} vs {sb!r}")
        return diffs

    if isinstance(val_a, str) and isinstance(val_b, str):
        try:
            val_a = json.loads(val_a)
            val_b = json.loads(val_b)
        except json.JSONDecodeError:
            from difflib import unified_diff
            diff_lines = list(unified_diff(
                val_a.splitlines(), val_b.splitlines(),
                fromfile=flow_id_a[:12], tofile=flow_id_b[:12], lineterm=""
            ))
            return "\n".join(diff_lines[:100]) if diff_lines else "Responses are identical."

    diffs = _schema_diff(val_a, val_b)
    if not diffs:
        return "Responses are structurally identical."
    return f"Found {len(diffs)} differences:\n" + "\n".join(diffs[:50])


@mcp.tool()
async def infer_response_schema(
    flow_id: str,
    max_depth: int = 4,
    sample_values: bool = True,
) -> str:
    """
    Infer a detailed JSON schema from a flow's response body — types, nesting, array item schemas, sample values.
    Much more detailed than get_flow_schema (which only does top-level keys).
    Args:
        flow_id: The ID of the captured flow
        max_depth: Maximum nesting depth to traverse (default: 4)
        sample_values: Include sample values for leaf fields (default: True)
    """
    body = controller.recorder.db.get_response_body(flow_id)
    if body is None:
        return "Flow not found."
    if not body:
        return "Flow has no response body."

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return "Response body is not valid JSON."

    def _infer(val, depth=0):
        if depth >= max_depth:
            return {"type": type(val).__name__, "note": "max_depth reached"}
        if val is None:
            return {"type": "null"}
        if isinstance(val, bool):
            return {"type": "bool", **({"sample": val} if sample_values else {})}
        if isinstance(val, int):
            return {"type": "int", **({"sample": val} if sample_values else {})}
        if isinstance(val, float):
            return {"type": "float", **({"sample": val} if sample_values else {})}
        if isinstance(val, str):
            result = {"type": "string", "length": len(val)}
            if sample_values:
                result["sample"] = val[:100]
            return result
        if isinstance(val, list):
            result = {"type": "array", "length": len(val)}
            if val:
                result["item_schema"] = _infer(val[0], depth + 1)
            return result
        if isinstance(val, dict):
            result = {"type": "object", "fields": len(val)}
            result["properties"] = {
                k: _infer(v, depth + 1) for k, v in val.items()
            }
            return result
        return {"type": type(val).__name__}

    schema = _infer(data)
    return json.dumps(schema, indent=2, ensure_ascii=False)


def start():
    """Entry point for running the server directly."""
    import argparse

    parser = argparse.ArgumentParser(description="mitmproxy-mcp server")
    parser.add_argument(
        "--dump-file",
        default=os.environ.get("MITMPROXY_DUMP_FILE"),
        help="Path to save raw .flow data. Prefix with + to append. "
        "Can also be set via MITMPROXY_DUMP_FILE env var.",
    )
    parser.add_argument(
        "--upstream-proxy",
        default=os.environ.get("MITMPROXY_UPSTREAM_PROXY"),
        help="Upstream proxy URL (e.g., http://user:pass@proxy:port). "
        "Can also be set via MITMPROXY_UPSTREAM_PROXY env var.",
    )
    args, _ = parser.parse_known_args()

    global controller
    # Store CLI upstream proxy if provided
    controller = MitmController(dump_file=args.dump_file)
    controller.cli_upstream_proxy = args.upstream_proxy

    mcp.run()


if __name__ == "__main__":
    start()
