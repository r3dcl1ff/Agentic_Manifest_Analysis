#Simple Agent that leverages Google ADK, apktool and Claude API to perform SAST of Android Manifest
#Change target model and tweak where appropriate
#imports as specified in requirements.txt file
import json
import os
import subprocess
import shutil
import asyncio
from datetime import datetime
from google.adk.agents import Agent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

# leverage apktool to extract code
def extract_manifest_with_apktool(apk_path: str) -> str:
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"Target APK not found: {apk_path}")
    
    output_dir = "apktool_out"
    manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
    
    try:
        cmd = ["apktool", "d", "-f", "-s", apk_path, "-o", output_dir] #check apktool syntax if changes are made
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        
        with open(manifest_path, "r", encoding="utf-8") as f:
            return f.read()
    finally:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir)

def save_report(apk_name: str, analysis_report: str, filename: str = "manifest_analysis.md"):

    report_header = f"""# Android Manifest Security Analysis Report
**Target Archive:** {apk_name}
**Generated On:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

---

"""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(report_header + analysis_report)

# ADK agent orchestration, tweak prompt if necessary
async def analyze_manifest_with_adk(manifest_data: str) -> str:
    
    system_instruction = """
You are a Senior Android Security Analyst. Perform a thorough static security analysis on the provided AndroidManifest.xml.

Your objective is to identify vulnerabilities, misconfigurations, and security risks. Focus specifically on:
- Exported Components (Activities, Services, Receivers, Providers)
- Dangerous, Custom, or Overly Permissive Permissions
- Debuggable or Backup flags enabled in production
- Implicit Intent Filters that could be intercepted
- Cleartext Traffic allowed
- Hardcoded metadata secrets (API keys, tokens)

INSTRUCTIONS:
1. Ignore standard Android boilerplate. Only flag items that present a legitimate security risk.
2. Structure your response EXACTLY using the following Markdown format:

## Executive Summary
[A brief 2-3 sentence overview of the overall security posture]

## Detailed Findings
[For each vulnerability found, use the following structure. If none are found, state "No significant vulnerabilities detected."]

### [Finding Name]
* **Severity:** [Critical/High/Medium/Low]
* **Component/Line:** [Name of the affected component or XML tag]
* **Description:** [What the issue is]
* **Impact:** [What an attacker could do with this]
* **Remediation:** [Actionable steps or XML code snippet to fix it]
"""

    security_agent = Agent(
        name="ManifestAnalyzer",
        model="anthropic/claude-sonnet-4-6",
        instruction=system_instruction,
    )

    app_name = "ManifestAnalyzerApp"
    session_id = "manifest_analysis_session"
    user_id = "local_analyst"
    session_service = InMemorySessionService()
    await session_service.create_session(
        app_name=app_name, 
        user_id=user_id, 
        session_id=session_id
    )

    runner = Runner(
        agent=security_agent,
        app_name=app_name,
        session_service=session_service
    )

    print("[*]🥋 Stage 3: Passing context to ADK Agent for vulnerability inference...")
    payload = f"TARGET ANDROIDMANIFEST.XML:\n{manifest_data}"
    content = types.Content(role='user', parts=[types.Part(text=payload)])
    final_report = "Agent did not produce a final response."

    async for event in runner.run_async(
        user_id=user_id,
        session_id=session_id,
        new_message=content
    ):
        if event.is_final_response():
            if event.content and event.content.parts:
                final_report = event.content.parts[0].text
    return final_report

def main():
    print("[*]🕶️  Stage 1: Loading configs...")
    with open("config.json", "r") as f:
        config = json.load(f)
        
    target_apk = config.get("target_apk")
    os.environ["ANTHROPIC_API_KEY"] = config.get("anthropic_api_key")
    
    print(f"[*]💥 Stage 2: Running Apktool to unpack and decode target apk '{target_apk}'...")
    manifest_xml = extract_manifest_with_apktool(target_apk)
    analysis_report = asyncio.run(analyze_manifest_with_adk(manifest_xml))
    print("[*]📝 Saving report to current directory...")
    save_report(target_apk, analysis_report)
    print(f"[+]🤯 BOMBOCLAAT! Manifest analysis generated at: {os.path.abspath('manifest_analysis.md')}")

if __name__ == "__main__":
    main()
