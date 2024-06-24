import idaapi
import idautils
import idc

# Function to create a unique function name
def make_unique_name(base_name, existing_names):
    if base_name not in existing_names:
        return base_name
    suffix = 1
    while f"{base_name}_{suffix}" in existing_names:
        suffix += 1
    return f"{base_name}_{suffix}"

# Function to get the string argument of a call instruction
def get_string_argument(call_addr):
    # Get the function frame (stack frame)
    f = idaapi.get_func(call_addr)
    if not f:
        return None
    
    # Get the list of argument addresses
    args = idaapi.get_arg_addrs(call_addr)
    if not args:
        return None

    for arg in args:
        operand = idc.get_operand_value(arg, 1)
        string_value = idc.get_strlit_contents(operand)
        if string_value:
            string_value = string_value.decode('utf-8')
            if "::" in string_value:
                return string_value.split(' ')[0]  # Extract the name until the first space
    return None

# Function to process a single function
def process_function(target_func_name):
    target_func_ea = idc.get_name_ea_simple(target_func_name)
    if target_func_ea == idc.BADADDR:
        print(f"Target function '{target_func_name}' not found.")
        return

    print(f"Target function '{target_func_name}' found at address {hex(target_func_ea)}.")

    # Set to store existing function names
    existing_names = set()

    # Iterate over all functions to collect existing names
    for func_ea in idautils.Functions():
        func_name = idc.get_func_name(func_ea)
        existing_names.add(func_name)

    # Iterate over all cross-references to the target function
    for xref in idautils.XrefsTo(target_func_ea):
        caller_func_ea = idc.get_func_attr(xref.frm, idc.FUNCATTR_START)
        if caller_func_ea != idc.BADADDR:
            # Get the string argument passed to the target function
            func_name = get_string_argument(xref.frm)
            if func_name:
                # Make a unique function name
                unique_func_name = make_unique_name(func_name, existing_names)
                if unique_func_name != func_name:
                    print(f"Function name '{func_name}' already exists. Renaming to '{unique_func_name}' to ensure uniqueness.")
                else:
                    print(f"Renaming function at {hex(caller_func_ea)} to '{unique_func_name}'.")

                # Rename the calling function
                if idc.set_name(caller_func_ea, unique_func_name, idc.SN_NOWARN):
                    print(f"Successfully renamed function at {hex(caller_func_ea)} to '{unique_func_name}'.")
                    existing_names.add(unique_func_name)
                else:
                    print(f"Failed to rename function at {hex(caller_func_ea)} to '{unique_func_name}'.")
            else:
                print(f"Failed to retrieve valid string argument for call at address {hex(xref.frm)}.")
        else:
            print(f"Failed to determine the calling function for xref at address {hex(xref.frm)}.")

# List of functions to process
target_functions = ["sub_7FFFF746D3E0"]

# Process each target function
for target_func_name in target_functions:
    process_function(target_func_name)

print("Script completed.")
