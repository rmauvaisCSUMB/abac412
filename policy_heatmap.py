import os
import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns


def extract_atomic_conditions_and_users(file_path):

    with open(file_path, 'r') as file:
        data = file.read()

    atomic_conditions = re.findall(r"#\s+(\w+):", data)
    users = re.findall(r"\b(oncdoc\d+|oncnurse\d+|otheruser\d+|[a-zA-Z]+\d+)\b", data)
    # deduplicate and sort results
    return sorted(set(atomic_conditions)), sorted(set(users))

def extract_rules(file_path):
    with open(file_path, 'r') as file:
        data = file.read()

    rule_pattern = re.compile(r"rule\((.*?\))", re.DOTALL)
    rules = rule_pattern.findall(data)
    return [rule.strip() for rule in rules]

def generate_heatmap_matrix(rules, attributes):
    heatmap_data = pd.DataFrame(0, index=rules, columns=attributes)
    # analyze rules for attributes
    for rule in rules:
        for attribute in attributes:
            if attribute.lower() in rule.lower():  
                heatmap_data.at[rule, attribute] += 1

    return heatmap_data

def plot_save_heatmap(data, filename = 'heatmap.png'):
    plt.figure(figsize=(12, 8))
    sns.heatmap(data, annot=True, cmap="YlGnBu", fmt="d")
    plt.title("Policy Coverage Heatmap")
    plt.xlabel("Attributes")
    plt.ylabel("Rules")
    plt.xticks(rotation=45, ha="right")
    plt.tight_layout()
    plt.show()

    plt.savefig(filename, dpi=300, bbox_inches="tight")


#main function with debugging
if __name__ == "__main__":
    # Hardcoded file path for healthcare.abac
    policy_file_path = os.path.join(os.getcwd(), "healthcare.abac")

    if not os.path.exists(policy_file_path):
        print(f"Error: '{policy_file_path}' does not exist in the current directory.")
    else:
        # extract atomic conditions, users, and rules
        atomic_conditions, users = extract_atomic_conditions_and_users(policy_file_path)
        rules = extract_rules(policy_file_path)

        # debug
        print(f"Extracted {len(rules)} rules:")
        print(rules)
        print(f"Extracted {len(atomic_conditions)} atomic conditions:")
        print(atomic_conditions)

        # heatmap matrix
        heatmap_matrix = generate_heatmap_matrix(rules, atomic_conditions)

        # debug
        print("Heatmap matrix (first 5 rows):")
        print(heatmap_matrix.head())

        # check if heatmap data is valid
        if heatmap_matrix.empty:
            print("Error: Heatmap matrix is empty. Ensure rules and attributes are extracted correctly.")
        else:
            # plot
            plot_save_heatmap(heatmap_matrix, filename="heatmap.png")

