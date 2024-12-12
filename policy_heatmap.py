import os
import re
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import argparse

def process_healthcare_abac(file_path):
    with open(file_path, 'r') as file:
        data = file.read()

    # Extract atomic conditions
    atomic_conditions = re.findall(r"#\s+(\w+):", data)

    # Extract rules
    rule_pattern = re.compile(r"rule\((.*?\))", re.DOTALL)
    rules = rule_pattern.findall(data)

    # Deduplicate and sort
    atomic_conditions = sorted(set(atomic_conditions))
    rules = sorted(set(rules))

    return atomic_conditions, rules

def process_university_abac(file_path):
    with open(file_path, 'r') as file:
        data = file.read()

    # Extract user and resource attributes
    user_attributes = re.findall(r"userAttrib\([^,]+,\s*([^)]+)\)", data)
    resource_attributes = re.findall(r"resourceAttrib\([^,]+,\s*([^)]+)\)", data)

    # Combine attributes into a single list
    attributes = []
    for attr_list in user_attributes + resource_attributes:
        attributes.extend(re.findall(r"(\w+)=\{?[^\s}]+", attr_list))  # Match attribute names

    # Extract rules
    rule_pattern = re.compile(r"rule\((.*?\))", re.DOTALL)
    rules = rule_pattern.findall(data)

    # Deduplicate and sort
    attributes = sorted(set(attributes))
    rules = sorted(set(rules))

    return attributes, rules

def generate_heatmap_matrix(rules, attributes):
    heatmap_data = pd.DataFrame(0, index=rules, columns=attributes)
    # analyze rules for attributes
    for rule in rules:
        for attribute in attributes:
            if attribute.lower() in rule.lower():  # Case-insensitive match
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
def main():
    # argument parser
    parser = argparse.ArgumentParser(description="Generate ABAC heatmap from a policy file.")
    parser.add_argument(
        "-a",
        "--abac",
        required=True,
        help="Path to the input ABAC policy file (.abac)."
    )

    args = parser.parse_args()
    file_path = args.abac

    # Determine processing function based on file name
    if "healthcare" in file_path.lower():
        processing_function = process_healthcare_abac
        output_filename = "healthcare_heatmap.png"
    elif "university" in file_path.lower():
        processing_function = process_university_abac
        output_filename = "university_heatmap.png"
    else:
        print("Error: Unsupported ABAC policy file. Ensure the file name includes 'healthcare' or 'university'.")
        return

    # Check if the file exists
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' does not exist.")
        return

    # Process the selected ABAC file
    attributes, rules = processing_function(file_path)

    # Debug: Print extracted rules and attributes
    print(f"Extracted {len(rules)} rules:")
    print(rules)
    print(f"Extracted {len(attributes)} attributes:")
    print(attributes)

    # Generate heatmap matrix
    heatmap_matrix = generate_heatmap_matrix(rules, attributes)

    # Debug: Check the heatmap matrix
    print("Heatmap matrix (first 5 rows):")
    print(heatmap_matrix.head())

    # Check if heatmap data is valid
    if heatmap_matrix.empty:
        print("Error: Heatmap matrix is empty. Ensure rules and attributes are extracted correctly.")
    else:
        # Save and plot the heatmap
        plot_and_save_heatmap(heatmap_matrix, filename=output_filename)


if __name__ == "__main__":
    main()
