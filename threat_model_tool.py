#!/usr/bin/env python3

import yaml
import openai
import os

# Fetch OpenAI API key from environment variable
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# Check if API key is set, otherwise exit
if not OPENAI_API_KEY:
    print("❌ ERROR: OpenAI API Key is missing. Please set it using `export OPENAI_API_KEY='your-api-key'`")
    exit(1)

# Initialize OpenAI client
client = openai.OpenAI(api_key=OPENAI_API_KEY)

# Define System Model
SYSTEM_MODEL_YAML = """
entities:
  - name: "Client"
    type: "External"
    trust_level: "Low"
  - name: "Service"
    type: "Internal"
    trust_level: "Medium"
  - name: "Database"
    type: "Internal"
    trust_level: "High"
flows:
  - source: "Client"
    destination: "Service"
    data_type: "Credentials"
    channel: "HTTPS"
  - source: "Service"
    destination: "Database"
    data_type: "User Data"
    channel: "SQL"
"""

def load_model(model_yaml):
    """Load and parse YAML system model"""
    return yaml.safe_load(model_yaml)

def analyze(model):
    """Analyze threats based on defined system model"""
    threats = []
    for flow in model["flows"]:
        if flow["channel"] == "HTTPS":
            threats.append({
                "flow": f"{flow['source']}->{flow['destination']}",
                "category": "Spoofing",
                "desc": "Identity of Client could be forged."
            })
            threats.append({
                "flow": f"{flow['source']}->{flow['destination']}",
                "category": "Tampering",
                "desc": "Credentials could be altered in transit over HTTPS."
            })
            threats.append({
                "flow": f"{flow['source']}->{flow['destination']}",
                "category": "Information Disclosure",
                "desc": "Credentials exposed if HTTPS is compromised."
            })
        if flow["channel"] == "SQL":
            threats.append({
                "flow": f"{flow['source']}->{flow['destination']}",
                "category": "Tampering",
                "desc": "User Data could be altered in transit over SQL."
            })
            threats.append({
                "flow": f"{flow['source']}->{flow['destination']}",
                "category": "Information Disclosure",
                "desc": "User Data exposed if SQL is compromised."
            })
    return threats

def generate_ai_mitigation(threats):
    """Generate AI-based threat mitigations using OpenAI GPT"""
    prompt = "Suggest mitigation strategies for the following security threats:\n"
    for threat in threats:
        prompt += f"- {threat['category']}: {threat['desc']}\n"

    try:
        response = client.chat.completions.create(
            model="gpt-4o",  # Ensure you have access to this model
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert providing detailed threat mitigations."},
                {"role": "user", "content": prompt}
            ]
        )
        return response.choices[0].message.content
    except openai.OpenAIError as e:
        return f"❌ ERROR: Failed to generate AI-based mitigations: {e}"

def main():
    """Main function to execute threat analysis and AI-based mitigations"""
    model = load_model(SYSTEM_MODEL_YAML)
    threats = analyze(model)

    print("\n=== Identified Threats ===\n")
    for threat in threats:
        print(f"- Flow: {threat['flow']}\n  Category: {threat['category']}\n  Description: {threat['desc']}\n")

    print("\n=== AI-Generated Mitigation Strategies ===\n")
    ai_suggestions = generate_ai_mitigation(threats)
    print(ai_suggestions)

if __name__ == "__main__":
    main()
