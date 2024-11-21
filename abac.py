# ABAC Policy Assignment 4
# CST 412
# Cao Thang Bui
# Members: Ryan Mauvais, Andre Manzo, Landon Wivell, Luis Edeza


import re
import matplotlib.pyplot as plt
from collections import defaultdict
# ABAC policies data structure
ABAC = []
# Function to parse attribute strings into a dictionary
def parse_attributes(attribute_string):
    """Parses the attribute string into a dictionary."""
    attribute_string = attribute_string.strip("{}[]")
    attributes = {}
    for attr in attribute_string.split(","):
        if "=" in attr:
            key, value = attr.split("=", 1)
            attributes[key.strip()] = parse_value(value.strip())
        else:
            attributes[attr.strip()] = True  # For boolean flags like isChair=true
    return attributes
def parse_value(value):
    """Parses attribute values into appropriate types."""
    if value.startswith("{") and value.endswith("}"):
        return value.strip("{}").split()  # Convert set-like attributes to list
    elif value.isdigit():
        return int(value)  # Convert numeric strings to integers
    elif value.lower() in ["true", "false"]:
        return value.lower() == "true"  # Convert to boolean
    return value  # Leave as string
# Function to load ABAC policies from a file
def load_abac(file_path):
    global ABAC
    ABAC.clear()  # Reset the ABAC list
    with open(file_path, 'r') as file:
        for line in file:
            line = line.strip()
            if not line or line.startswith("#"):
                continue  # Skip comments and empty lines
            if line.startswith("userAttrib"):
                match = re.match(r"userAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    user, attributes = match.groups()
                    ABAC.append({"type": "userAttrib", "id": user, "attributes": parse_attributes(attributes)})
            elif line.startswith("resourceAttrib"):
                match = re.match(r"resourceAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    resource, attributes = match.groups()
                    ABAC.append({"type": "resourceAttrib", "id": resource, "attributes": parse_attributes(attributes)})
            elif line.startswith("rule"):
                match = re.match(r"rule\((.+?),\"(\w+)\"\)", line)
                if match:
                    condition, action = match.groups()
                    ABAC.append({"type": "rule", "condition": condition, "action": action})
    print(f"Loaded ABAC policies from {file_path}.")
# Function to evaluate a single request
def evaluate_request(sub_id, res_id, action):
    user_attrs = {}
    resource_attrs = {}
    # Extract user and resource attributes
    for item in ABAC:
        if item["type"] == "userAttrib" and item["id"] == sub_id:
            user_attrs = item["attributes"]
        elif item["type"] == "resourceAttrib" and item["id"] == res_id:
            resource_attrs = item["attributes"]
    # Evaluate rules
    for item in ABAC:
        if item["type"] == "rule":
            condition = item["condition"]
            rule_action = item["action"]
            try:
                if eval(condition, {"sub": user_attrs, "res": resource_attrs}) and rule_action == action:
                    return "PERMIT"
            except Exception as e:
                print(f"Error evaluating condition: {condition}. Error: {e}")
                return "DENY"
    return "DENY"
# Function to evaluate requests from a file
def evaluate_requests(file_path):
    with open(file_path, 'r') as file:
        for line in file:
            sub_id, res_id, action = line.strip().split(',')
            result = evaluate_request(sub_id, res_id, action)
            print(f"{sub_id},{res_id},{action}: {result}")
# Function for policy coverage analysis
def policy_coverage_analysis():
    rule_coverage = defaultdict(int)
    attribute_coverage = defaultdict(set)
    print("ABAC Policies Loaded for Analysis:")
    for policy in ABAC:
        print(policy)
    for idx, item in enumerate(ABAC):
        if item["type"] == "rule":
            condition = item["condition"]
            for sub_item in ABAC:
                if sub_item["type"] == "userAttrib":
                    sub_attrs = sub_item["attributes"]
                    for res_item in ABAC:
                        if res_item["type"] == "resourceAttrib":
                            res_attrs = res_item["attributes"]
                            try:
                                if eval(condition, {"sub": sub_attrs, "res": res_attrs}):
                                    rule_coverage[idx] += 1
                                    attribute_coverage[idx].update(sub_attrs.keys())
                                    attribute_coverage[idx].update(res_attrs.keys())
                            except Exception as e:
                                print(f"Error evaluating rule {idx}: {condition}. Error: {e}")
    # Debugging: print the coverage data
    print("\nRule Coverage Data:")
    for idx, coverage in rule_coverage.items():
        print(f"Rule {idx + 1}: {coverage} authorizations covered.")
    # Debugging: print the attributes covered for each rule
    print("\nAttribute Coverage Data:")
    for idx, attributes in attribute_coverage.items():
        print(f"Rule {idx + 1} covers attributes: {attributes}")
    # Prepare the heatmap data
    rules = [f"Rule {i + 1}" for i in range(len(ABAC)) if ABAC[i]["type"] == "rule"]
    attributes = sorted(set(attr for attrs in attribute_coverage.values() for attr in attrs))
    heatmap_data = [[1 if attr in attribute_coverage[i] else 0 for attr in attributes] for i in range(len(rules))]
    # Debugging: print the heatmap data matrix
    print("\nHeatmap Data Matrix:")
    print(heatmap_data)
    if not heatmap_data or not any(heatmap_data):
        print("No data available to generate a heatmap. Ensure the ABAC policies and attributes are loaded correctly.")
        return
    # Plot the heatmap
    plt.figure(figsize=(10, 8))
    plt.imshow(heatmap_data, cmap='Blues', interpolation='nearest')
    plt.xticks(range(len(attributes)), attributes, rotation=45, ha='right')
    plt.yticks(range(len(rules)), rules)
    plt.colorbar(label='Attribute Coverage Intensity')
    plt.title('Policy Coverage Heatmap')
    plt.show()
# Main menu function
def menu():
    while True:
        print("\n1. Load ABAC policies.")
        print("2. Evaluate access requests from a file.")
        print("3. Perform policy coverage analysis.")
        print("4. Exit.")
        choice = input("Choose an option: ")
        if choice == '1':
            file_path = input("Enter file path to load ABAC policies: ")
            load_abac(file_path)
        elif choice == '2':
            file_path = input("Enter file path to evaluate access requests: ")
            evaluate_requests(file_path)
        elif choice == '3':
            policy_coverage_analysis()
        elif choice == '4':
            print("Exiting program.")
            break
        else:
            print("Invalid choice. Please select again.")
if __name__ == "__main__":
    menu()