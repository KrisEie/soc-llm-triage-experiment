# triage_suricata.py
import os
import json
import base64
import time
import argparse
from datetime import datetime
from dotenv import load_dotenv
import google.generativeai as gen

# Load environment variables
load_dotenv()
GEMINI_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-1.5-flash") # Default to flash if not set

if not GEMINI_KEY:
    raise RuntimeError("Missing GOOGLE_API_KEY in .env")

# Configure Gemini
gen.configure(api_key=GEMINI_KEY)
# Using a generation config to enforce JSON response (where supported) or low temp
GEN_CFG = {
    "response_mime_type": "application/json", 
    "temperature": 0.1
}

SYSTEM_PROMPT = (
    "You are a Tier 1 SOC Analyst. Your job is to analyze individual Suricata alerts from a Windows Proxy / Web Server environment. "
    "Analyze the provided alert JSON and return a STRICT JSON assessment. "
    "Do NOT engage in conversation, only output the JSON object."
)

def decode_payload(b64_str):
    """
    Decodes base64 payload to a safe string representation.
    Replaces non-printable characters.
    """
    if not b64_str:
        return ""
    try:
        decoded_bytes = base64.b64decode(b64_str)
        # Try to decode as utf-8, replace errors
        return decoded_bytes.decode('utf-8', errors='replace')
    except Exception as e:
        return f"<Error decoding payload: {str(e)}>"

def build_prompt(alert):
    """
    Constructs the prompt for the LLM.
    """
    # Extract key fields for the prompt to keep it focused (though we send the full cleaned JSON)
    rule_name = alert.get('rule', {}).get('name', 'Unknown')
    src_ip = alert.get('source', {}).get('ip')
    dest_ip = alert.get('destination', {}).get('ip')
    
    prompt_text = f"""
Analyze the following Suricata alert. 
The environment consists of an attacker (192.168.250.106) targeting a victim web server (192.168.250.59).

Alert Rule: {rule_name}
Source: {src_ip}
Destination: {dest_ip}

Review the full alert details below, paying close attention to the `payload_decoded` field which contains the HTTP request/response.

Return a JSON object with this exact schema:
{{
  "decision": "informational" | "benign" | "suspicious" | "likely natural",
  "likelihood": <float between 0.0 and 1.0>,
  "attack_type": "<short label, e.g., XSS, SQLi, Nmap Scan>",
  "cve": ["<list of potential CVEs or 'unknown'>"],
  "mitre_attack": [
    {{"id": "<Technique ID>", "description": "<Technique Name>"}}
  ],
  "reasons": ["<list of evidence-based reasons referencing specific fields like payload content, user-agent, etc.>"],
  "next_steps": ["<list of concrete actions for a human analyst>"]
}}

Alert JSON:
```json
{json.dumps(alert, indent=2)}
```
"""
    return prompt_text

def analyze_alert(model, alert):
    """
    Sends alert to Gemini and parses response.
    """
    # Pre-process: decode payload if present
    if 'payload_base64' in alert:
        alert['payload_decoded'] = decode_payload(alert['payload_base64'])
    elif 'suricata' in alert and 'payload_base64' in alert['suricata']:
         # Some structures might have it nested
         alert['payload_decoded'] = decode_payload(alert['suricata']['payload_base64'])
    
    # Also handle the payload_base64 directly in the root or inner structures if user mentioned it specifically
    # based on the example in the prompt, it seems it handles the provided alert structure.
    # The user provided file has 'payload_base64' at the root level of the structure provided in the text description? 
    # Let's check the previous `view_file` output.
    # Ah, in the file: "payload_base64": "..." is inside the root object? 
    # Wait, looking at file content:
    # {"timestamp": ..., "rule": ..., "suricata": { ..., "payload_base64": "...", ...}}
    # Actually, in the `view_file` output for line 1, `payload_base64` is inside the `suricata` object? No, looking closely at line 1:
    # It seems `payload_base64` is a top-level key or inside `suricata`?
    # Line 2: ... "suricata": { ... "http": { ... }, "payload_base64": "..." ... }
    # So `payload_base64` IS inside the `suricata` object in the example lines shown? 
    # Wait, in line 2 output: `"suricata": {"alert": ..., "http": ..., "payload_base64": "..."}`. Yes.
    # But let's write code that finds it wherever it is or just decodes relevant fields.
    
    # Safer approach: Decode known base64 fields in place for the LLM
    alert_copy = json.loads(json.dumps(alert)) # Deep copy
    
    if 'payload_base64' in alert_copy:
        alert_copy['payload_decoded'] = decode_payload(alert_copy['payload_base64'])
        # Optionally remove the massive base64 string to save context window if needed, but keeping it is fine for now.
    
    if 'suricata' in alert_copy and isinstance(alert_copy['suricata'], dict):
        if 'payload_base64' in alert_copy['suricata']:
            alert_copy['suricata']['payload_decoded'] = decode_payload(alert_copy['suricata']['payload_base64'])

    prompt = build_prompt(alert_copy)
    
    try:
        response = model.generate_content(prompt)
        # Parse output
        response_text = response.text.strip()
        
        # Strip markdown code blocks if present
        if response_text.startswith("```json"):
            response_text = response_text[7:]
        if response_text.startswith("```"):
            response_text = response_text[3:]
        if response_text.endswith("```"):
            response_text = response_text[:-3]
            
        result_json = json.loads(response_text)
        return result_json
    except Exception as e:
        return {
            "decision": "error",
            "error_msg": str(e),
            "raw_response": getattr(response, 'text', '') if 'response' in locals() else ''
        }

def main():
    parser = argparse.ArgumentParser(description="Offline Suricata Alert Triage with Gemini")
    parser.add_argument("input_file", help="Path to input .jsonl file")
    parser.add_argument("--output", help="Path to output .jsonl file", default=None)
    parser.add_argument("--limit", type=int, help="Limit number of alerts to process", default=0)
    
    args = parser.parse_args()
    
    input_path = args.input_file
    output_path = args.output or f"triage_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jsonl"
    
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found.")
        return

    print(f"Initializing Gemini model: {GEMINI_MODEL}")
    model = gen.GenerativeModel(GEMINI_MODEL, system_instruction=SYSTEM_PROMPT, generation_config=GEN_CFG)
    
    print(f"Processing alerts from {input_path}...")
    
    count = 0
    with open(input_path, 'r', encoding='utf-8') as f_in, open(output_path, 'w', encoding='utf-8') as f_out:
        for line in f_in:
            if not line.strip():
                continue
            
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                print("Skipping invalid JSON line")
                continue
            
            triage_result = analyze_alert(model, alert)
            
            # Combine original alert ID/timestamp with triage result
            output_record = {
               "timestamp": alert.get('@timestamp'),
               "event_id": alert.get('event', {}).get('id'),
               "rule": alert.get('rule', {}).get('name'),
               "triage": triage_result
            }
            
            f_out.write(json.dumps(output_record) + "\n")
            f_out.flush()
            
            decision = triage_result.get('decision', 'N/A')
            print(f"[{count+1}] Processed alert: {alert.get('rule', {}).get('name')} -> {decision}")
            
            count += 1
            if args.limit > 0 and count >= args.limit:
                break
                
            # Rate limiting to avoid hitting free tier limits aggressively
            time.sleep(2) 

    print(f"Finished! Processed {count} alerts.")
    print(f"Results saved to {output_path}")

if __name__ == "__main__":
    main()
