# ABAC Policy Assignment 4
# CST 412
# Cao Thang Bui
# Members: Ryan Mauvais, Andre Manzo, Landon Wivell, Luis Edeza

import argparse
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

# Function to fix unclosed brackets in ABAC policy lines
def fix_unclosed_brackets(line):
    """Fix unclosed brackets by appending missing ones."""
    open_brackets = line.count("[") + line.count("(")
    close_brackets = line.count("]") + line.count(")")
    missing_brackets = open_brackets - close_brackets
    if missing_brackets > 0:
        if "[" in line:
            line += "]" * missing_brackets
        if "(" in line:
            line += ")" * missing_brackets
    return line

# Function to normalize semicolon placement
def normalize_semicolons(line):
    """Normalize semicolon placement in the rule."""
    if "; type" in line or "; position" in line:
        line = line.replace("; type", " type").replace("; position", " position")
    return line

# Function to map uid= to user attributes
def map_uid_to_user(line, user_mapping):
    """Map uid= values to corresponding user attributes."""
    if "uid=" in line:
        uid = line.split("uid=")[-1].strip(")")
        if uid in user_mapping:
            line = line.replace(f"uid={uid}", f"user={uid}")
    return line

# Function to parse a single rule line
def parse_rule(line):
    """Parse and normalize a single rule line."""
    line = fix_unclosed_brackets(line)
    line = normalize_semicolons(line)
    return line

# Function to parse and normalize an ABAC policy file
def parse_policy_file(file_path, user_mapping):
    """Parse the ABAC policy file and normalize its content."""
    parsed_lines = []
    with open(file_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("#") and line:  # Ignore comments and empty lines
                line = map_uid_to_user(line, user_mapping)
                line = parse_rule(line)
            parsed_lines.append(line)
    return parsed_lines

# Function to load ABAC policies from a file
def load_abac(file_path):
    """Loads ABAC policies from the file."""
    global ABAC
    ABAC.clear()  # Reset the ABAC list

    try:
        with open(file_path, "r") as file:
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
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")

# Function to evaluate a single request
def evaluate_request(sub_id, res_id, action):
    """Evaluates a single access request."""
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
    """Evaluates multiple requests from a file."""
    try:
        with open(file_path, "r") as file:
            for line in file:
                sub_id, res_id, action = line.strip().split(',')
                result = evaluate_request(sub_id, res_id, action)
                print(f"{sub_id},{res_id},{action}: {result}")
    except FileNotFoundError:
        print(f"Error: File not found: {file_path}")

# Function for policy coverage analysis and heatmap generation
def policy_coverage_analysis():
    """Analyzes policy coverage and generates a heatmap."""
    rule_coverage = defaultdict(int)
    attribute_coverage = defaultdict(set)

    print("ABAC Policies Loaded for Analysis:")
    for policy in ABAC:
        print(policy)

    # Loop through all rules and evaluate them
    for idx, item in enumerate(ABAC):
        if item["type"] == "rule":
            condition = item["condition"]
            print(f"Evaluating Rule {idx + 1}: {condition}")  # Debugging print
            for sub_item in ABAC:
                if sub_item["type"] == "userAttrib":
                    sub_attrs = sub_item["attributes"]
                    print(f"  User Attributes: {sub_attrs}")  # Debugging print
                    for res_item in ABAC:
                        if res_item["type"] == "resourceAttrib":
                            res_attrs = res_item["attributes"]
                            print(f"  Resource Attributes: {res_attrs}")  # Debugging print
                            try:
                                # Debugging the eval
                                result = eval(condition, {"sub": sub_attrs, "res": res_attrs})
                                print(f"    Condition Result: {result}")  # Debugging print

                                if result:
                                    rule_coverage[idx] += 1
                                    attribute_coverage[idx].update(sub_attrs.keys())
                                    attribute_coverage[idx].update(res_attrs.keys())
                            except Exception as e:
                                print(f"Error evaluating rule {idx}: {condition}. Error: {e}")

    # Debugging: Print the coverage data
    print("\nRule Coverage Data:")
    for idx, coverage in rule_coverage.items():
        print(f"Rule {idx + 1}: {coverage} authorizations covered.")

    # Debugging: Print the attributes covered for each rule
    print("\nAttribute Coverage Data:")
    for idx, attributes in attribute_coverage.items():
        print(f"Rule {idx + 1} covers attributes: {attributes}")

    # Prepare the heatmap data
    rules = [f"Rule {i + 1}" for i in range(len(ABAC)) if ABAC[i]["type"] == "rule"]
    attributes = sorted(set(attr for attrs in attribute_coverage.values() for attr in attrs))
    heatmap_data = [[1 if attr in attribute_coverage[i] else 0 for attr in attributes] for i in range(len(rules))]

    # Debugging: Print the heatmap data matrix
    print("\nHeatmap Data Matrix:")
    print(heatmap_data)

    # Display the heatmap if there is data
    if not heatmap_data or not any(heatmap_data):
        print("No data available to generate a heatmap. Ensure the ABAC policies and attributes are loaded correctly.")
        return

    plt.figure(figsize=(10, 8))
    plt.imshow(heatmap_data, cmap='Blues', interpolation='nearest')
    plt.xticks(range(len(attributes)), attributes, rotation=45, ha='right')
    plt.yticks(range(len(rules)), rules)
    plt.colorbar(label='Attribute Coverage Intensity')
    plt.title('Policy Coverage Heatmap')
    plt.show()


# Function for resource access analysis
def resource_access_analysis():
    """Analyzes resource access and generates a bar graph."""
    access_counts = defaultdict(int)

    for item in ABAC:
        if item["type"] == "resourceAttrib":
            resource = item["id"]
            access_counts[resource] += 1

    # Generate bar graph
    resources = list(access_counts.keys())
    counts = list(access_counts.values())

    plt.figure(figsize=(10, 6))
    plt.bar(resources, counts, color='skyblue')
    plt.xticks(rotation=45, ha='right')
    plt.xlabel('Resources')
    plt.ylabel('Access Count')
    plt.title('Resource Access Analysis')
    plt.tight_layout()
    plt.show()

# Main function to handle command-line arguments
def main():
    parser = argparse.ArgumentParser(description="ABAC Policy Management System")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command: load_abac
    load_abac_parser = subparsers.add_parser("load_abac", help="Load ABAC policies from a file")
    load_abac_parser.add_argument("file", type=str, help="Path to the ABAC file")

    # Command: evaluate
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate access requests from a file")
    evaluate_parser.add_argument("file", type=str, help="Path to the requests file")

    # Command: policy_analysis
    policy_analysis_parser = subparsers.add_parser("policy_analysis", help="Perform policy coverage analysis")

    # Command: resource_analysis
    resource_analysis_parser = subparsers.add_parser("resource_analysis", help="Perform resource access analysis")

    # Parse the arguments
    args = parser.parse_args()

    # Handle each command
    if args.command == "load_abac":
        load_abac(args.file)
    elif args.command == "evaluate":
        evaluate_requests(args.file)
    elif args.command == "policy_analysis":
        policy_coverage_analysis()
    elif args.command == "resource_analysis":
        resource_access_analysis()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
