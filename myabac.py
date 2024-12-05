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

# Global list to store ABAC policies
ABAC = []

def parse_attributes(attribute_string):
    """
    Parses a string of attributes into a dictionary.

    Parameters:
        attribute_string (str): A string representing attributes, e.g., 'role=admin, level=5'

    Returns:
        dict: A dictionary of attributes with their parsed values.
    """
    attributes = {}
    # Split the attribute string by commas, handling possible spaces and ensuring splitting at '='
    for attr in re.split(r',\s*(?=\w+=)', attribute_string):
        # Split each attribute into key and value
        key, value = attr.split('=', 1)
        # Strip whitespace and parse the value
        attributes[key.strip()] = parse_value(value.strip())
    return attributes

def parse_value(value):
    """
    Parses a value string into its appropriate type.

    Parameters:
        value (str): The value to parse, possibly a set in braces.

    Returns:
        list or str: A list if the value represents a set, or a string otherwise.
    """
    value = value.strip()
    if value.startswith("{") and value.endswith("}"):
        # The value is a set of values, remove braces and split
        return [v.strip() for v in value.strip('{}').split()]
    else:
        # Return as is (string)
        return value  # Atomic value

def parse_conditions(cond_string):
    """
    Parses a string of conditions into a list of condition dictionaries.

    Parameters:
        cond_string (str): The condition string, e.g.,
            'position [ {manager director}, department ] sales'

    Returns:
        list: A list of condition dictionaries with keys 'type', 'attr', and other relevant keys.
    """
    conditions = []
    if not cond_string:
        # If the condition string is empty, return an empty list
        return conditions
    # Split the condition string by commas
    for cond in cond_string.split(','):
        cond = cond.strip()
        if '[' in cond:
            # Condition is of type 'in', e.g., 'position [ {manager director}'
            match = re.match(r'(\w+)\s*\[\s*\{(.+?)\}', cond)
            if match:
                attr, values = match.groups()
                # Split the values inside the braces into a list
                values = values.strip().split()
                conditions.append({'type': 'in', 'attr': attr, 'values': values})
        elif ']' in cond:
            # Condition is of type 'contains', e.g., 'department ] sales'
            match = re.match(r'(\w+)\s*\]\s*(\w+)', cond)
            if match:
                attr, value = match.groups()
                conditions.append({'type': 'contains', 'attr': attr, 'value': value})
    return conditions

def parse_actions(acts_string):
    """
    Parses an actions string into a list of actions.

    Parameters:
        acts_string (str): The actions string, e.g., '{read write}' or 'delete'

    Returns:
        list: A list of action strings.
    """
    acts_string = acts_string.strip()
    if acts_string.startswith('{') and acts_string.endswith('}'):
        # Multiple actions inside braces
        return [act.strip() for act in acts_string.strip('{}').split()]
    else:
        # Single action
        return [acts_string]

def parse_constraints(cons_string):
    """
    Parses a string of constraints into a list of constraint dictionaries.

    Parameters:
        cons_string (str): The constraints string, e.g., 'aum > arm, aus = ars'

    Returns:
        list: A list of constraint dictionaries with 'type', 'left', 'right' keys.
    """
    constraints = []
    if not cons_string:
        # If the constraints string is empty, return an empty list
        return constraints
    # Split the constraints string by commas
    for cons in cons_string.split(','):
        cons = cons.strip()
        if '>' in cons:
            # Constraint is of type 'superset', e.g., 'aum > arm'
            left, right = cons.split('>')
            constraints.append({'type': 'superset', 'left': left.strip(), 'right': right.strip()})
        elif '[' in cons:
            # Constraint is of type 'in_attr', e.g., 'aus [ arm'
            left, right = cons.split('[')
            constraints.append({'type': 'in_attr', 'left': left.strip(), 'right': right.strip()})
        elif ']' in cons:
            # Constraint is of type 'contains_attr', e.g., 'aum ] ars'
            left, right = cons.split(']')
            constraints.append({'type': 'contains_attr', 'left': left.strip(), 'right': right.strip()})
        elif '=' in cons:
            # Constraint is of type 'equal', e.g., 'aus = ars'
            left, right = cons.split('=')
            constraints.append({'type': 'equal', 'left': left.strip(), 'right': right.strip()})
    return constraints

def load_abac(file_path):
    """
    Loads ABAC policies from a policy file into the global ABAC list.

    Parameters:
        file_path (str): The path to the policy file.

    The policy file can contain:
        - userAttrib(user_id, attributes)
        - resourceAttrib(resource_id, attributes)
        - rule(sub_cond; res_cond; actions; constraints)
    """
    global ABAC
    # Clear the existing policies
    ABAC.clear()
    with open(file_path, 'r') as file:
        # Iterate over each line in the policy file
        for line_num, line in enumerate(file, 1):
            line = line.strip()
            # Ignore empty lines and comments
            if not line or line.startswith("#"):
                continue
            if line.startswith("userAttrib"):
                # Parse user attributes
                match = re.match(r"userAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    uid, attributes = match.groups()
                    attributes = parse_attributes(attributes)
                    attributes['uid'] = uid  # Assign uid attribute
                    ABAC.append({"type": "userAttrib", "id": uid, "attributes": attributes})
                else:
                    print(f"Error parsing user attribute at line {line_num}: {line}")
            elif line.startswith("resourceAttrib"):
                # Parse resource attributes
                match = re.match(r"resourceAttrib\((\w+),\s*(.+)\)", line)
                if match:
                    rid, attributes = match.groups()
                    attributes = parse_attributes(attributes)
                    attributes['rid'] = rid  # Assign rid attribute
                    ABAC.append({"type": "resourceAttrib", "id": rid, "attributes": attributes})
                else:
                    print(f"Error parsing resource attribute at line {line_num}: {line}")
            elif line.startswith("rule"):
                # Parse rules
                rule_content = line[len("rule("):-1]  # Remove 'rule(' and the closing ')'
                if ';' in rule_content:
                    parts = rule_content.split(';')
                    if len(parts) != 4:
                        print(f"Error parsing rule at line {line_num}: {line}")
                        continue
                    # Extract subject conditions, resource conditions, actions, and constraints
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
    """
    Evaluates a list of conditions against the provided attributes.

    Parameters:
        conditions (list): A list of condition dictionaries.
        attrs (dict): The attributes to evaluate against.

    Returns:
        bool: True if all conditions are satisfied, False otherwise.
    """
    for cond in conditions:
        if cond['type'] == 'in':
            # Condition requires that attr_value is in specified values
            attr_value = attrs.get(cond['attr'])
            if attr_value not in cond['values']:
                return False  # Condition not satisfied
        elif cond['type'] == 'contains':
            # Condition requires that attr_values (list) contains cond['value']
            attr_values = attrs.get(cond['attr'], [])
            if not isinstance(attr_values, list):
                attr_values = [attr_values]
            if cond['value'] not in attr_values:
                return False  # Condition not satisfied
    return True  # All conditions are satisfied

def evaluate_constraints(constraints, sub_attrs, res_attrs):
    """
    Evaluates a list of constraints between subject and resource attributes.

    Parameters:
        constraints (list): A list of constraint dictionaries.
        sub_attrs (dict): Subject attributes.
        res_attrs (dict): Resource attributes.

    Returns:
        bool: True if all constraints are satisfied, False otherwise.
    """
    for cons in constraints:
        if cons['type'] == 'superset':
            # Subject's left attribute values must be a superset of resource's right attribute values
            left_values = sub_attrs.get(cons['left'], [])
            right_values = res_attrs.get(cons['right'], [])
            if not isinstance(left_values, list):
                left_values = [left_values]
            if not isinstance(right_values, list):
                right_values = [right_values]
            if not set(left_values).issuperset(right_values):
                return False  # Constraint not satisfied
        elif cons['type'] == 'in_attr':
            # Subject's left attribute value must be in resource's right attribute values
            left_value = sub_attrs.get(cons['left'])
            right_values = res_attrs.get(cons['right'], [])
            if not isinstance(right_values, list):
                right_values = [right_values]
            if left_value not in right_values:
                return False  # Constraint not satisfied
        elif cons['type'] == 'contains_attr':
            # Subject's left attribute values must contain resource's right attribute value
            left_values = sub_attrs.get(cons['left'], [])
            if not isinstance(left_values, list):
                left_values = [left_values]
            right_value = res_attrs.get(cons['right'])
            if right_value not in left_values:
                return False  # Constraint not satisfied
        elif cons['type'] == 'equal':
            # Subject's left attribute value must equal resource's right attribute value
            left_value = sub_attrs.get(cons['left'])
            right_value = res_attrs.get(cons['right'])
            if left_value != right_value:
                return False  # Constraint not satisfied
    return True  # All constraints are satisfied

def evaluate_request(sub_id, res_id, action):
    """
    Evaluates if a request is permitted based on the loaded policies.

    Parameters:
        sub_id (str): Subject (user) identifier.
        res_id (str): Resource identifier.
        action (str): Action requested.

    Returns:
        str: "Permit" if access is allowed, "Deny" otherwise.
    """
    # Retrieve user and resource attributes
    user_attrs = {}
    resource_attrs = {}
    for item in ABAC:
        if item["type"] == "userAttrib" and item["id"] == sub_id:
            user_attrs = item["attributes"]
        elif item["type"] == "resourceAttrib" and item["id"] == res_id:
            resource_attrs = item["attributes"]
    # Check if user and resource attributes are found
    if not user_attrs or not resource_attrs:
        print(f"User or resource attributes not found for {sub_id}, {res_id}")
        return "Deny"
    # Evaluate each rule
    for item in ABAC:
        if item["type"] == "rule":
            sub_cond = item["sub_cond"]
            res_cond = item["res_cond"]
            actions = item["actions"]
            constraints = item["constraints"]
            # Check if the action matches
            if action not in actions:
                continue  # Action not in rule's actions
            # Evaluate subject conditions
            if not evaluate_conditions(sub_cond, user_attrs):
                continue  # Subject conditions not met
            # Evaluate resource conditions
            if not evaluate_conditions(res_cond, resource_attrs):
                continue  # Resource conditions not met
            # Evaluate constraints
            if not evaluate_constraints(constraints, user_attrs, resource_attrs):
                continue  # Constraints not satisfied
            # All conditions and constraints satisfied
            return "Permit"
    # No rule permits the request
    return "Deny"

def evaluate_requests(policy_file, request_file):
    """
    Evaluates access requests from a request file using the policies from a policy file.

    Parameters:
        policy_file (str): Path to the policy file.
        request_file (str): Path to the request file.

    The request file should contain lines in the format:
        sub_id,res_id,action
    """
    # Load policies from policy file
    load_abac(policy_file)
    with open(request_file, 'r') as file:
        # Iterate over each request in the request file
        for line_num, line in enumerate(file, 1):
            parts = line.strip().split(',')
            if len(parts) != 3:
                print(f"Invalid request format at line {line_num}: {line.strip()}")
                continue
            sub_id, res_id, action = parts
            # Evaluate the request
            result = evaluate_request(sub_id.strip(), res_id.strip(), action.strip())
            # Output the result
            print(f"{sub_id.strip()},{res_id.strip()},{action.strip()}: {result}")

def policy_coverage_analysis(policy_file):
    """
    Performs policy coverage analysis by generating a heatmap showing
    which user positions have access to which actions.

    Parameters:
        policy_file (str): Path to the policy file.
    """
    # Load policies from policy file
    load_abac(policy_file)
    # Collect all possible user positions and actions
    positions = set()
    actions = set()
    for item in ABAC:
        if item["type"] == "userAttrib":
            position = item["attributes"].get("position")
            if position:
                positions.add(position)
        elif item["type"] == "rule":
            actions.update(item["actions"])
    # Sort positions and actions for consistent ordering
    positions = sorted(positions)
    actions = sorted(actions)
    # Initialize the coverage matrix (positions x actions)
    coverage = np.zeros((len(positions), len(actions)), dtype=int)
    # Map positions and actions to indices in the matrix
    position_indices = {pos: idx for idx, pos in enumerate(positions)}
    action_indices = {act: idx for idx, act in enumerate(actions)}
    # Analyze coverage by checking which positions have rules permitting which actions
    for rule in [item for item in ABAC if item["type"] == "rule"]:
        sub_conds = rule["sub_cond"]
        rule_actions = rule["actions"]
        for cond in sub_conds:
            if cond['type'] == 'in' and cond['attr'] == 'position':
                for pos in cond['values']:
                    if pos in position_indices:
                        for act in rule_actions:
                            if act in action_indices:
                                # Increment the coverage count for this position-action pair
                                coverage[position_indices[pos]][action_indices[act]] += 1
    # Plot the heatmap using seaborn
    plt.figure(figsize=(10, 6))
    sns.heatmap(coverage, annot=True, fmt="d", xticklabels=actions, yticklabels=positions, cmap="YlGnBu")
    plt.xlabel("Actions")
    plt.ylabel("User Positions")
    plt.title("Policy Coverage Heatmap")
    plt.show()


# def analyze_resource_access_patterns(policy_file):
#     """
#     Analyzes resource access patterns by identifying resources with the most and least
#     access permissions and generates bar graphs for the top 10 resources.

#     Parameters:
#         policy_file (str): Path to the policy file.
#     """
#     # Load policies from policy file
#     load_abac(policy_file)

#     # Dictionary to hold the count of permissions per resource
#     resource_permission_counts = defaultdict(int)

#     # Collect all resources and actions they are associated with in the rules
#     for rule in [item for item in ABAC if item["type"] == "rule"]:
#         res_conds = rule["res_cond"]
#         rule_actions = rule["actions"]

#         # Find resources that match the resource conditions
#         for res_item in [item for item in ABAC if item["type"] == "resourceAttrib"]:
#             resource_id = res_item["id"]
#             resource_attrs = res_item["attributes"]

#             # Check if the resource meets the conditions in the rule
#             if evaluate_conditions(res_conds, resource_attrs):
#                 # Increment the count for this resource by the number of actions
#                 resource_permission_counts[resource_id] += len(rule_actions)

#     # Sort resources by permission counts
#     sorted_resources = sorted(resource_permission_counts.items(), key=lambda x: x[1], reverse=True)

#     # Get top 10 resources with the highest access
#     top_resources = sorted_resources[:10]

#     # Get top 10 resources with the lowest access (excluding resources with zero permissions)
#     bottom_resources = [item for item in sorted_resources if item[1] > 0][-10:]

#     # Prepare data for plotting top resources
#     top_resource_ids = [item[0] for item in top_resources]
#     top_permission_counts = [item[1] for item in top_resources]

#     # Prepare data for plotting bottom resources
#     bottom_resource_ids = [item[0] for item in bottom_resources]
#     bottom_permission_counts = [item[1] for item in bottom_resources]

#     # Plot bar graph for top 10 resources with highest access
#     plt.figure(figsize=(10, 6))
#     plt.bar(top_resource_ids, top_permission_counts, color='green')
#     plt.xlabel("Resource IDs")
#     plt.ylabel("Number of Permissions")
#     plt.title("Top 10 Resources with Highest Access Permissions")
#     plt.xticks(rotation=45)
#     plt.tight_layout()
#     plt.show()

#     # Plot bar graph for top 10 resources with lowest access
#     plt.figure(figsize=(10, 6))
#     plt.bar(bottom_resource_ids, bottom_permission_counts, color='red')
#     plt.xlabel("Resource IDs")
#     plt.ylabel("Number of Permissions")
#     plt.title("Top 10 Resources with Lowest Access Permissions")
#     plt.xticks(rotation=45)
#     plt.tight_layout()
#     plt.show()

if __name__ == "__main__":
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="ABAC Framework Driver Program")
    parser.add_argument("-e", nargs=2, metavar=('policy_file', 'request_file'),
                        help="Evaluate requests: specify the policy file and request file")
    parser.add_argument("-a", metavar='policy_file',
                        help="Analyze policy coverage: specify the policy file")
    parser.add_argument("-b", metavar='policy_file',
                        help="Analyze resource access patterns: specify the policy file")
    args = parser.parse_args()

    # Determine which action to perform based on arguments
    if args.e:
        # Evaluate requests
        evaluate_requests(args.e[0], args.e[1])
    elif args.a:
        # Perform policy coverage analysis
        policy_coverage_analysis(args.a)
    elif args.b:
        # Analyze resource access patterns
        analyze_resource_access_patterns(args.b)
    else:
        # No valid option provided
        print("Invalid option. Use -h for help.")
