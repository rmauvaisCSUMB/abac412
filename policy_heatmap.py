import re
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# File path to the .abac file
file_path = "healthcare.abac"

# Function to parse user attributes
def parse_user_attributes(content):
    user_attrib_pattern = r"userAttrib\(([\w\d]+),\s*position=([\w]+),\s*(.*)\)"
    user_attributes = []
    for line in content:
        match = re.match(user_attrib_pattern, line)
        if match:
            user_id = match.group(1)
            position = match.group(2)
            other_attributes = match.group(3).strip()
            user_attributes.append((user_id, position, other_attributes))
    return pd.DataFrame(user_attributes, columns=["UserID", "Position", "Attributes"])

# Refined function to parse and format rules
def parse_rules(content):
    # Rule regex to capture everything inside 'rule()' or equivalent structure
    rule_pattern = r"rule\((.*?)\)"
    rules = []
    for line in content:
        match = re.search(rule_pattern, line)
        if match:
            # Extract the rule content
            rule_content = match.group(1).strip()
            # Clean up the rule content for better readability
            formatted_rule = rule_content.replace("[", "").replace("]", "").replace(";", ",")
            rules.append(formatted_rule)
    return rules


# Generate a heatmap
def generate_heatmap(attributes, rules, output_file="heatmap.png"):
    # Create a mapping of rules to attributes
    rule_attribute_map = {}
    for i, rule in enumerate(rules):
        for attribute in attributes:
            if attribute in rule:
                if rule not in rule_attribute_map:
                    rule_attribute_map[rule] = []
                rule_attribute_map[rule].append(attribute)
    
    # Create a DataFrame for the heatmap
    heatmap_data = pd.DataFrame(0, index=rules, columns=attributes)
    for rule, attrs in rule_attribute_map.items():
        for attr in attrs:
            heatmap_data.loc[rule, attr] = 1

    # Plot the heatmap
    plt.figure(figsize=(10, len(rules) * 0.5))
    sns.heatmap(heatmap_data, annot=True, cmap="Blues", cbar=False)
    plt.title("Policy Rule Coverage Heatmap")
    plt.xlabel("Attributes")
    plt.ylabel("Rules")
    plt.tight_layout()
    plt.savefig(output_file)
    plt.close()

# Main function
def main():
    # Read the .abac file
    with open(file_path, "r") as file:
        content = file.readlines()
    
    # Parse user attributes
    user_attributes = parse_user_attributes(content)
    print("User Attributes:")
    print(user_attributes.head())

    # Parse rules
    rules = parse_rules(content)
    print("\nRules Found:")
    print(rules)

    # Extract unique attributes
    unique_attributes = user_attributes["Attributes"].str.extractall(r"(\w+)")[0].unique()

    # Generate heatmap
    generate_heatmap(unique_attributes, rules)
    print("\nHeatmap saved as 'heatmap.png'.")

# Run the script
if __name__ == "__main__":
    main()
