# Mobile SAST Manifest Analysis Agent

This specialized mobile SAST agent for manifest analysis leverages `apktool` for deterministic extraction, then utilizes the Google ADK and Sonnet API to perform automated security reviews. It autonomously surfaces critical deployment risks, improper permissions, and exposed components, delivering a finalized, actionable security report.

---

## Prerequisites

Before running the agent, ensure you have `apktool` installed and accessible via your system's PATH environment variable.
* **Linux:** `sudo apt install apktool`
* **macOS:** `brew install apktool`

---

## Installation

Install the necessary Python ecosystem dependencies using `pip3`:

```bash
pip3 install -r requirements.txt
```

---

## Configuration

Create a `config.json` file in the root directory of your project and populate it with your target application path and Anthropic API credentials:

```json
{
  "target_apk": "path/to/your/target.apk",
  "anthropic_api_key": "your-anthropic-api-key-here"
}
```

---

## Usage

Run the agent execution pipeline with the following command:

```bash
python3 agent.py
```

### Functions
1. **Extraction:** Decodes the `AndroidManifest.xml` natively using `apktool`.
2. **Orchestration:** Spins up the asynchronous Google ADK `Runner` and handles state tracking
3. **Analysis:** Routes the context to Claude 4.6 Sonnet to infer vulnerabilities, tweak the main prompt if necessary!
4. **Reporting:** Exports a formatted Markdown threat report named `manifest_analysis.md` directly into your workspace.
