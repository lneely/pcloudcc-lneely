#!/bin/bash

# Display help if requested
if [[ "$1" == "-h" || "$1" == "--help" ]]; then
    echo "Usage: $(basename "$0") [OPTIONS]"
    echo
    echo "Reads 'oldpattern => newpattern' pairs from STDIN and replaces all occurrences"
    echo "of oldpattern with newpattern in all .c and .h files in the current directory"
    echo "and its subdirectories."
    echo
    echo "OPTIONS:"
    echo "  -h, --help    Display this help and exit"
    echo
    echo "EXAMPLES:"
    echo "  cat patterns.txt | $(basename "$0")"
    echo "  $(basename "$0") < patterns.txt"
    echo
    echo "  Or interactively:"
    echo "  $(basename "$0")"
    echo "  oldFunction => newFunction"
    echo "  oldStruct => newStruct"
    echo "  [Ctrl+D to end input]"
    exit 0
fi

# Process each line from STDIN
while IFS= read -r line; do
    # Skip empty lines
    if [[ -z "$line" ]]; then
        continue
    fi
    
    # Check if the line contains "=>"
    if echo "$line" | grep -q "=>"; then
        # Extract old and new patterns
        oldpattern=$(echo "$line" | cut -d "=" -f 1 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        newpattern=$(echo "$line" | cut -d ">" -f 2 | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
        
        # Escape special characters for sed
        oldpattern_escaped=$(echo "$oldpattern" | sed 's/[\/&]/\\&/g')
        newpattern_escaped=$(echo "$newpattern" | sed 's/[\/&]/\\&/g')
        
        # echo "Replacing: '$oldpattern' with '$newpattern'"
        
        # Execute the find and sed command
        find . -name "*.[ch]" -exec sed -i "s/$oldpattern_escaped/$newpattern_escaped/g" {} \;
    else
        echo "Warning: Line does not match the 'oldpattern => newpattern' format: $line" >&2
    fi
done

# echo "All replacements completed!"