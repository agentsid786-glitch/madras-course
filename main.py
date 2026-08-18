from fastapi import FastAPI, Request
import re

app = FastAPI()

@app.post("/release-gate")
async def release_gate(request: Request):
    payload = await request.json()
    violations = []
    
    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")
    workflow = payload.get("workflow", {})
    image = payload.get("image", {})
    
    # 1. Permissions Strict Match
    allowed_perms = {"contents": "read", "packages": "write", "id-token": "none"}
    if workflow.get("permissions", {}) != allowed_perms:
        violations.append("EXCESS_PERMISSION")
        
    # 2. PR trigger rules
    trigger = workflow.get("trigger")
    if event == "pull_request" and trigger != "pull_request":
        violations.append("UNSAFE_PR_TRIGGER")
    elif trigger == "pull_request_target":
        if "UNSAFE_PR_TRIGGER" not in violations:
            violations.append("UNSAFE_PR_TRIGGER")
            
    # 3. Tests completion & FailFast
    if workflow.get("testsPassed") is not True or \
       workflow.get("matrixComplete") is not True or \
       workflow.get("failFast") is not False:
        violations.append("TESTS_INCOMPLETE")
        
    # 4. Action Pinning Check (Owner != actions must use 40-char SHA)
    for action in workflow.get("actions", []):
        if action.get("owner") != "actions":
            if not re.match(r'^[0-9a-f]{40}$', action.get("ref", "")):
                violations.append("MUTABLE_ACTION")
                break
                
    # 5. Image Stage
    if image.get("multiStage") is not True:
        violations.append("SINGLE_STAGE_IMAGE")
        
    # 6. Root runtime
    if image.get("runsAsRoot") is not False:
        violations.append("ROOT_RUNTIME")
        
    # 7. Secret in Layer mode
    if image.get("secretMode") not in ["none", "buildkit"]:
        violations.append("SECRET_IN_LAYER")
        
    # 8. Critical vulnerabilities
    if image.get("criticalVulnerabilities") != 0:
        violations.append("CRITICAL_CVE")
        
    # 9. Pinned image
    if image.get("digestPinned") is not True:
        violations.append("UNPINNED_IMAGE")
        
    # 10 & 11. Production Requirements
    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            violations.append("INVALID_PRODUCTION_REF")
        if workflow.get("environmentApproval") is not True:
            violations.append("APPROVAL_REQUIRED")
            
    # Final output
    return {
        "decision": "promote" if not violations else "block",
        "violations": violations
    }
