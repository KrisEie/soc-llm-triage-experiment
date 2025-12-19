# triage_experiment.py
import os
import json
import base64
import time
import argparse
import glob
from datetime import datetime
from dotenv import load_dotenv
import google.generativeai as gen
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

# Load environment variables
load_dotenv()
GEMINI_KEY = os.getenv("GOOGLE_API_KEY")
if not GEMINI_KEY:
    raise RuntimeError("Missing GOOGLE_API_KEY in .env")

gen.configure(api_key=GEMINI_KEY)

# Configurations
GEMINI_FLASH_MODEL = "models/gemini-2.5-flash"
GEMINI_PRO_MODEL = "models/gemini-2.5-pro"
LLAMA_MODEL_ID = "meta-llama/Llama-3.2-3B-Instruct"

# Global Llama model cache
llama_model = None
llama_tokenizer = None

def decode_payload(b64_str):
    if not b64_str: return ""
    try:
        return base64.b64decode(b64_str).decode('utf-8', errors='replace')
    except:
        return "<Error decoding>"

SYSTEM_PROMPT_TEXT = (
    "You are a Tier 1 SOC Analyst. Analyze the Suricata alert and return a STRICT JSON assessment. "
    "Do NOT engage in conversation, only output the JSON object."
)

def get_rag_context(alert):
    """
    Simple keyword-based RAG from knowledge_base.txt
    """
    kb_path = os.path.join("data", "knowledge_base.txt")
    if not os.path.exists(kb_path):
        return ""
    
    context = []
    rule_name = alert.get('rule', {}).get('name', '').lower()
    
    # Simple keyword matching
    keywords = {
        "xss": ["xss", "cross-site scripting", "javascript"],
        "wordpress": ["wordpress", "wp-login", "plugin"],
        "nmap": ["nmap", "scan"],
        "cleartext": ["cleartext", "credentials", "plain text"],
        "login": ["login", "authentication"]
    }
    
    found_keys = []
    for k, v in keywords.items():
        if any(x in rule_name for x in v):
            found_keys.append(k)
            
    if not found_keys:
        return ""

    try:
        with open(kb_path, 'r', encoding='utf-8') as f:
            content = f.read()
            # This is a very dumb retriever: just returns the distinct paragraphs containing keywords
            # Improvements: proper vector DB or embeddings. For POC, this is fine.
            paragraphs = content.split('\n\n')
            for p in paragraphs:
                if any(key in p.lower() for key in found_keys):
                    context.append(p)
    except Exception as e:
        print(f"RAG Error: {e}")
        
    return "\n\n".join(context[:3]) # Limit to top 3 snippets

def build_prompt_str(alert, rag_context=""):
    # Extract decoded payload
    payload_decoded = ""
    if 'payload_base64' in alert:
        payload_decoded = decode_payload(alert['payload_base64'])
    elif 'suricata' in alert and 'payload_base64' in alert['suricata']:
        payload_decoded = decode_payload(alert['suricata']['payload_base64'])
    
    alert_copy = json.loads(json.dumps(alert))
    alert_copy['payload_decoded'] = payload_decoded
    
    rag_section = ""
    if rag_context:
        rag_section = f"\nRelevant Cyber Threat Intelligence:\n{rag_context}\n"
    
    return f"""
Analyze the following Suricata alert. 
The environment consists of an attacker (192.168.250.106) targeting a victim web server (192.168.250.59).
{rag_section}
Review the alert details below. Pay attention to `payload_decoded`.

Return a JSON object with schema:
{{
  "decision": "informational" | "benign" | "suspicious" | "likely natural",
  "likelihood": <float 0.0-1.0>,
  "attack_type": "<short label>",
  "cve": ["<list>"],
  "mitre_attack": [{{"id": "Txxxx", "description": "Name"}}],
  "reasons": ["<list of evidence>"],
  "next_steps": ["<list of actions>"]
}}

Alert JSON:
```json
{json.dumps(alert_copy, indent=2)}
```
Only output the JSON.
"""

def load_llama():
    global llama_model, llama_tokenizer
    if llama_model is None:
        print(f"Loading Llama model: {LLAMA_MODEL_ID}")
        llama_tokenizer = AutoTokenizer.from_pretrained(LLAMA_MODEL_ID)
        llama_tokenizer.pad_token = llama_tokenizer.eos_token
        
        quant_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_compute_dtype=torch.float16,
            bnb_4bit_quant_type="nf4"
        )
        
        llama_model = AutoModelForCausalLM.from_pretrained(
            LLAMA_MODEL_ID,
            quantization_config=quant_config,
            device_map="auto",
            torch_dtype=torch.float16
        )

def run_gemini(model_name, prompt):
    try:
        model = gen.GenerativeModel(model_name, system_instruction=SYSTEM_PROMPT_TEXT, 
                                  generation_config={"response_mime_type": "application/json", "temperature": 0.1})
        resp = model.generate_content(prompt)
        return json.loads(resp.text)
    except Exception as e:
        return {"error": str(e)}

def run_llama(prompt):
    load_llama()
    
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT_TEXT},
        {"role": "user", "content": prompt}
    ]
    
    text = llama_tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    inputs = llama_tokenizer(text, return_tensors="pt").to("cuda")
    
    with torch.no_grad():
        outputs = llama_model.generate(
            **inputs,
            max_new_tokens=1024,
            temperature=0.1,
            do_sample=False,
            pad_token_id=llama_tokenizer.eos_token_id
        )
    
    # Slice off prompt tokens to get only new tokens
    # Or just decode everything and split. Llama 3 instruct format usually puts explanation after header.
    # But generate returns input+output by default usually unless configured otherwise?
    # Actually Model.generate returns full sequence.
    # Let's simple decode and split by header if needed, or substring.
    # Better: usage `outputs[0][inputs.input_ids.shape[1]:]`
    resp_tokens = outputs[0][inputs.input_ids.shape[1]:]
    resp_text = llama_tokenizer.decode(resp_tokens, skip_special_tokens=True)
    
    # Try to extract JSON
    try:
        s = resp_text.find('{')
        e = resp_text.rfind('}')
        if s != -1 and e != -1:
            return json.loads(resp_text[s:e+1])
        return {"error": "No JSON found in Llama output", "raw": resp_text}
    except Exception as e:
        return {"error": str(e), "raw": resp_text}

def main():
    input_file = os.path.join("data", "suri_windows_proxy.jsonl")
    if not os.path.exists(input_file):
        print("Input file not found!")
        return

    # Prepare outputs
    models = ["gemini_flash", "gemini_pro", "llama_plain", "llama_rag"]
    files = {m: open(os.path.join("results", f"suricata_triage_{m}.jsonl"), 'w', encoding='utf-8') for m in models}
    comparison_file = open(os.path.join("results", "comparison_combined.jsonl"), 'w', encoding='utf-8')
    
    print("Starting Multi-Model Triage Experiment...")
    
    alerts = []
    with open(input_file, 'r') as f:
        for i, line in enumerate(f):
            if i >= 6: break
            if line.strip():
                alerts.append(json.loads(line))
                
    for i, alert in enumerate(alerts):
        print(f"Processing Alert {i+1}/{len(alerts)}: {alert.get('rule', {}).get('name')}")
        
        results = {}
        
        # 1. Gemini Flash
        print("  - Gemini Flash...")
        results["gemini_flash"] = run_gemini(GEMINI_FLASH_MODEL, build_prompt_str(alert))
        
        # 2. Gemini Pro
        print("  - Gemini Pro...")
        results["gemini_pro"] = run_gemini(GEMINI_PRO_MODEL, build_prompt_str(alert))

        # 3. Llama Plain
        print("  - Llama Plain...")
        results["llama_plain"] = run_llama(build_prompt_str(alert))
        
        # 4. Llama RAG
        print("  - Llama RAG...")
        rag_context = get_rag_context(alert)
        results["llama_rag"] = run_llama(build_prompt_str(alert, rag_context))
        
        # Save individually
        for m in models:
            rec = {"alert_id": alert.get("event", {}).get("id"), "triage": results[m]}
            files[m].write(json.dumps(rec) + "\n")
            files[m].flush()
            
        # Save comparison
        comp_rec = {
            "alert_id": alert.get("event", {}).get("id"),
            "timestamp": alert.get("@timestamp"),
            "rule": alert.get('rule', {}).get('name'),
            "results": results
        }
        comparison_file.write(json.dumps(comp_rec) + "\n")
        comparison_file.flush()
        
        time.sleep(1) # Polite delay

    # Close files
    for f in files.values(): f.close()
    comparison_file.close()
    print("Experiment Complete! Results in 'results/' folder.")

if __name__ == "__main__":
    main()
