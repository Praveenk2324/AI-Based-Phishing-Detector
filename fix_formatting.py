file_path = "all_code.txt"

with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_lines = []
i = 0
while i < len(lines):
    line = lines[i]
    new_lines.append(line)
    
    # Check if this line is a decorator
    if line.strip().startswith("@"):
        # Look ahead for 'def ' or 'async def '
        # The spacing script might have inserted empty lines immediately after this line.
        # We want to remove them if the NEXT non-empty line starts with 'def '.
        
        # Scan ahead
        j = i + 1
        empty_indices = []
        is_function_next = False
        
        while j < len(lines):
            next_line = lines[j]
            if not next_line.strip():
                empty_indices.append(j)
                j += 1
            elif next_line.strip().startswith("def ") or next_line.strip().startswith("async def "):
                is_function_next = True
                break
            else:
                # Some other code/comment, so the space is valid/unrelated
                break
        
        if is_function_next and empty_indices:
            # We found a function following a decorator with gaps.
            # We skip adding the empty lines to 'new_lines'.
            # But wait, we are iterating.
            # My current structure is: append line, then move i.
            # Since I already appended the decorator line, I need to skip the empty lines in the MAIN loop.
            
            # Let's adjust the main loop index to skip 'empty_indices'
            # But wait, 'new_lines' is built sequentially. 
            # I can't look ahead and modify the iterator easily without robust buffering.
            pass

# Let's use a simpler approach: Read all, filter list.
cleaned_lines = []
skip_next_empty = False

for idx, line in enumerate(lines):
    stripped = line.strip()
    
    # If the previous meaningful line was a decorator, acts as glue?
    # No, traversing is easier with a window or just multiple passes.
    
    # Let's use the memory-entire-file approach.
    pass

# Re-implementation
final_lines = []
buffer_empty = [] # Store empty lines temporarily

for line in lines:
    if not line.strip():
        buffer_empty.append(line)
    else:
        # Meaningful line.
        # Check if it's a function def
        if line.strip().startswith("def ") or line.strip().startswith("async def "):
            # Check if previous meaningful line in final_lines was a decorator
            # We need to peek at final_lines backwards
            is_decorated = False
            if final_lines:
                last_content = final_lines[-1].strip()
                if last_content.startswith("@"):
                     is_decorated = True
            
            if is_decorated:
                # Discard buffered empty lines (or maybe keep just one? No, usually tight binding)
                # Decorators usually sit right on top.
                buffer_empty = [] 
        
        # Flush buffer
        final_lines.extend(buffer_empty)
        buffer_empty = []
        final_lines.append(line)

# Flush remaining
final_lines.extend(buffer_empty)

with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(final_lines)

print("Fixed decorator spacing.")
