# ABAC Policy Assignment 4
# CST 412
# Cao Thang Bui
# Members: Ryan Mauvais, Andre Manzo, Landon Wivell, Luis Edeza

import argparse
import re
import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
from collections import defaultdict
ABAC = []
def parse_attributes(attribute_string):
    """Parses attribute strings into a dictionary."""
    attributes = {}
    for attr in re.split(r',\s*(?=\w+=)', attribute_string):
        key, value = attr.split('=', 1)
        attributes[key.strip()] = parse_value(value.strip())
    return attributes
def parse_value(value):
    """Parses attribute values into appropriate types."""
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        # Set of values
        return [v.strip() for v in value.strip('{}').split()]
    else:
        return value  # Atomic value
def parse_conditions(cond_string):
    """Parses condition strings into a list of conditions."""
    conditions = []
    if not cond_string:
        return conditions
    for cond in cond_string.split(','):
        cond = cond.strip()
        if '[' in cond:
            # Handle 'attr [ {value1 value2 ...}'
            match = re.match(r'(\w+)\s*\[\s*\{(.+?)\}', cond)
            if match:
                attr, values = match.groups()
                values = values.strip().split()
                conditions.append({'type': 'in', 'attr': attr, 'values': values})
        elif ']' in cond:
            # Handle 'attr ] value'
            match = re.match(r'(\w+)\s*\]\s*(\w+)', cond)
            if match:
                attr, value = match.groups()
                conditions.append({'type': 'contains', 'attr': attr, 'value': value})
    return conditions
def parse_actions(acts_string):
    """Parses actions string into a list of actions."""
    acts_string = acts_string.strip()
    if acts_string.startswith('{') and acts_string.endswith('}'):
        return [act.strip() for act in acts_string.strip('{}').split()]
    else:
        return [acts_string]
def parse_constraints(cons_string):
    """Parses constraint strings into a list of constraints."""
    constraints = []
    if not cons_string:
        return constraints
    for cons in cons_string.split(','):
        cons = cons.strip()
        if '>' in cons:
            # Handle 'aum > arm'
            left, right = cons.split('>')
            constraints.append({'type': 'superset', 'left': left.strip(), 'right': right.strip()})
        elif '[' in cons:
            # Handle 'aus [ arm'
            left, right = cons.split('[')
            constraints.append({'type': 'in_attr', 'left': left.strip(), 'right': right.strip()})
        elif ']' in cons:
            # Handle 'aum ] ars'
            left, right = cons.split(']')
            constraints.append({'type': 'contains_attr', 'left': left.strip(), 'right': right.strip()})
        elif '=' in cons:
            # Handle 'aus = ars'
            left, right = cons.split('=')
            constraints.append({'type': 'equal', 'left': left.strip(), 'right': right.strip()})
    return constraints
def load_abac(file_path):
    """Loads ABAC policies from a .abac file."""
    global ABAC
    ABAC.clear()
    with open(file_path, 'r') as file:
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("userAttrib"):
                match = re.match(r"userAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    uid, attributes = match.groups()
                    attributes = parse_attributes(attributes)
                    attributes['uid'] = uid  # Assign uid attribute
                    ABAC.append({"type": "userAttrib", "id": uid, "attributes": attributes})
                else:
                    print(f"Error parsing user attribute at line {line_num}: {line}")
            elif line.startswith("resourceAttrib"):
                match = re.match(r"resourceAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    rid, attributes = match.groups()
                    attributes = parse_attributes(attributes)
                    attributes['rid'] = rid  # Assign rid attribute
                    ABAC.append({"type": "resourceAttrib", "id": rid, "attributes": attributes})
                else:
                    print(f"Error parsing resource attribute at line {line_num}: {line}")
            elif line.startswith("rule"):
                rule_content = line[len("rule("):-1]  # Remove 'rule(' and the closing ')'
                if ';' in rule_content:
                    parts = rule_content.split(';')
                    if len(parts) != 4:
                        print(f"Error parsing rule at line {line_num}: {line}")
                        continue
                    sub_cond, res_cond, acts, cons = map(str.strip, parts)
                    ABAC.append({
                        "type": "rule",
                        "sub_cond": parse_conditions(sub_cond),
                        "res_cond": parse_conditions(res_cond),
                        "actions": parse_actions(acts),
                        "constraints": parse_constraints(cons)
                    })
                else:
                    print(f"Error parsing rule at line {line_num}: {line}")
            else:
                print(f"Unrecognized line at line {line_num}: {line}")
def evaluate_conditions(conditions, attrs):
    """Evaluates a list of conditions against given attributes."""
    for cond in conditions:
        if cond['type'] == 'in':
            attr_value = attrs.get(cond['attr'])
            if attr_value not in cond['values']:
                return False
        elif cond['type'] == 'contains':
            attr_values = attrs.get(cond['attr'], [])
            if not isinstance(attr_values, list):
                attr_values = [attr_values]
            if cond['value'] not in attr_values:
                return False
    return True
def evaluate_constraints(constraints, sub_attrs, res_attrs):
    """Evaluates a list of constraints."""
    for cons in constraints:
        if cons['type'] == 'superset':
            left_values = sub_attrs.get(cons['left'], [])
            right_values = res_attrs.get(cons['right'], [])
            if not isinstance(left_values, list):
                left_values = [left_values]
            if not isinstance(right_values, list):
                right_values = [right_values]
            if not set(left_values).issuperset(right_values):
                return False
        elif cons['type'] == 'in_attr':
            left_value = sub_attrs.get(cons['left'])
            right_values = res_attrs.get(cons['right'], [])
            if not isinstance(right_values, list):
                right_values = [right_values]
            if left_value not in right_values:
                return False
        elif cons['type'] == 'contains_attr':
            left_values = sub_attrs.get(cons['left'], [])
            if not isinstance(left_values, list):
                left_values = [left_values]
            right_value = res_attrs.get(cons['right'])
            if right_value not in left_values:
                return False
        elif cons['type'] == 'equal':
            left_value = sub_attrs.get(cons['left'])
            right_value = res_attrs.get(cons['right'])
            if left_value != right_value:
                return False
    return True
def evaluate_request(sub_id, res_id, action):
    """Evaluates if a request is permitted."""
    user_attrs = {}
    resource_attrs = {}
    for item in ABAC:
        if item["type"] == "userAttrib" and item["id"] == sub_id:
            user_attrs = item["attributes"]
        elif item["type"] == "resourceAttrib" and item["id"] == res_id:
            resource_attrs = item["attributes"]
    if not user_attrs or not resource_attrs:
        print(f"User or resource attributes not found for {sub_id}, {res_id}")
        return "Deny"
    for item in ABAC:
        if item["type"] == "rule":
            sub_cond = item["sub_cond"]
            res_cond = item["res_cond"]
            actions = item["actions"]
            constraints = item["constraints"]
            if action not in actions:
                continue
            if not evaluate_conditions(sub_cond, user_attrs):
                continue
            if not evaluate_conditions(res_cond, resource_attrs):
                continue
            if not evaluate_constraints(constraints, user_attrs, resource_attrs):
                continue
            return "Permit"
    return "Deny"
def evaluate_requests(policy_file, request_file):
    """Evaluate access requests from a file."""
    load_abac(policy_file)
    with open(request_file, 'r') as file:
        for line_num, line in enumerate(file, 1):
            parts = line.strip().split(',')
            if len(parts) != 3:
                print(f"Invalid request format at line {line_num}: {line.strip()}")
                continue
            sub_id, res_id, action = parts
            result = evaluate_request(sub_id.strip(), res_id.strip(), action.strip())
            print(f"{sub_id.strip()},{res_id.strip()},{action.strip()}: {result}")
def policy_coverage_analysis(policy_file):
    """Perform policy coverage analysis and generate a heatmap."""
    load_abac(policy_file)
    # Collect all possible combinations of user positions and actions
    positions = set()
    actions = set()
    for item in ABAC:
        if item["type"] == "userAttrib":
            position = item["attributes"].get("position")
            if position:
                positions.add(position)
        elif item["type"] == "rule":
            actions.update(item["actions"])
    positions = sorted(positions)
    actions = sorted(actions)
    # Initialize the coverage matrix
    coverage = np.zeros((len(positions), len(actions)), dtype=int)
    # Map positions to indices
    position_indices = {pos: idx for idx, pos in enumerate(positions)}
    # Map actions to indices
    action_indices = {act: idx for idx, act in enumerate(actions)}
    # Analyze coverage
    for rule in [item for item in ABAC if item["type"] == "rule"]:
        sub_conds = rule["sub_cond"]
        rule_actions = rule["actions"]
        for cond in sub_conds:
            if cond['type'] == 'in' and cond['attr'] == 'position':
                for pos in cond['values']:
                    if pos in position_indices:
                        for act in rule_actions:
                            if act in action_indices:
                                coverage[position_indices[pos]][action_indices[act]] += 1
    # Plot the heatmap
    plt.figure(figsize=(10, 6))
    sns.heatmap(coverage, annot=True, fmt="d", xticklabels=actions, yticklabels=positions, cmap="YlGnBu")
    plt.xlabel("Actions")
    plt.ylabel("User Positions")
    plt.title("Policy Coverage Heatmap")
    plt.show()

def analyze_resource_access(policy_file):
    """Analyze resource access patterns and generate bar graphs."""
    load_abac(policy_file)
    action_counts = defaultdict(int)
    # Count how many times each action is allowed by the rules
    for rule in [item for item in ABAC if item["type"] == "rule"]:
        for act in rule["actions"]:
            action_counts[act] += 1
    # Plot the bar graph
    actions = list(action_counts.keys())
    counts = [action_counts[act] for act in actions]
    plt.figure(figsize=(8, 6))
    plt.bar(actions, counts, color='skyblue')
    plt.xlabel("Actions")
    plt.ylabel("Number of Rules Allowing Action")
    plt.title("Resource Access Pattern Analysis")
    plt.show()
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ABAC Framework Driver Program")
    parser.add_argument("-e", nargs=2, metavar=('policy_file', 'request_file'),
                        help="Evaluate requests: specify the policy file and request file")
    parser.add_argument("-a", metavar='policy_file',
                        help="Analyze policy coverage: specify the policy file")
    parser.add_argument("-b", metavar='policy_file',
                        help="Analyze resource access patterns: specify the policy file")
    args = parser.parse_args()
    if args.e:
        evaluate_requests(args.e[0], args.e[1])
    elif args.a:
        policy_coverage_analysis(args.a)
    elif args.b:
        analyze_resource_access(args.b)
    else:
        print("Invalid option. Use -h for help.")
