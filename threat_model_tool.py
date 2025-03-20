#!/usr/bin/env python3
import yaml

import os
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

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

def load_model(m):
    return yaml.safe_load(m)

def print_context(d):
    print("=== MICROSOFT THREAT MODEL (STRIDE) ===\n")
    print("Entities:")
    for e in d.get("entities", []):
        print(f"  - Name: {e['name']}")
        print(f"    Type: {e['type']}")
        print(f"    Trust: {e['trust_level']}")
        print()
    print("Flows:")
    for f in d.get("flows", []):
        print(f"  - {f['source']} -> {f['destination']}")
        print(f"    Data: {f['data_type']}")
        print(f"    Channel: {f['channel']}")
        print()

def analyze(d):
    r = []
    for f in d.get("flows", []):
        s,dst,dt,c = f["source"],f["destination"],f["data_type"],f["channel"]
        r.append({"flow":f"{s}->{dst}","cat":"Spoofing","desc":f"Identity of {s} could be forged."})
        r.append({"flow":f"{s}->{dst}","cat":"Tampering","desc":f"{dt} could be altered in transit over {c}."})
        r.append({"flow":f"{s}->{dst}","cat":"Repudiation","desc":f"No proof of actions from {s} to {dst}."})
        r.append({"flow":f"{s}->{dst}","cat":"Information Disclosure","desc":f"{dt} exposed if {c} is compromised."})
        r.append({"flow":f"{s}->{dst}","cat":"Denial of Service","desc":f"{c} blocked or flooded."})
        r.append({"flow":f"{s}->{dst}","cat":"Elevation of Privilege","desc":f"{s} could gain higher rights on {dst}."})
    return r

def print_threats(i):
    print("Threats:")
    for x in i:
        print(f"  - Flow: {x['flow']}")
        print(f"    Category: {x['cat']}")
        print(f"    Description: {x['desc']}")
        print()

def main():
    model = load_model(SYSTEM_MODEL_YAML)
    print_context(model)
    threats = analyze(model)
    print_threats(threats)

if __name__ == "__main__":
    main()
