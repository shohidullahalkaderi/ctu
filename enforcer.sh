#!/usr/bin/env bash
#
# Production-Hardened Universal Security Enforcer: Memory Corruption & Race Condition Defense
#

WRAPPER_PATH="/usr/local/bin/g++"

cat << 'EOF' > "$WRAPPER_PATH"
#!/usr/bin/env bash

# PART 1: C/C++ Memory Corruption & Bypass Defense

# 1. Block flags used to bypass memory protections
FORBIDDEN_COMPILER_FLAGS=(
    "-fno-stack-protector"
    "execstack"
    "-no-pie"
    "-fno-pie"
)

for arg in "$@"; do
    for flag in "${FORBIDDEN_COMPILER_FLAGS[@]}"; do
        if [[ "$arg" == *"$flag"* ]]; then
            echo -e "\033[0;31m[SECURITY VIOLATION] Compilation Blocked (Memory Protection Bypass)!\033[0m" >&2
            echo -e "\033[0;33mForbidden bypass flag detected: '$flag'\033[0m" >&2
            exit 1
        fi
    done
done

# 2. Extract source files for static analysis
SOURCE_FILES=()
for arg in "$@"; do
    if [[ "$arg" == *.cpp ]] || [[ "$arg" == *.cc ]] || [[ "$arg" == *.c ]] || [[ "$arg" == *.cxx ]]; then
        SOURCE_FILES+=("$arg")
    fi
done

HAS_MULTITHREADING=false

for src in "${SOURCE_FILES[@]}"; do
    if [ -f "$src" ]; then
        
        # --- VECTOR A: Memory Corruption (BOF Precursors) ---
        if grep -qE "\b(strcpy|strcat|sprintf|gets)\s*\(" "$src" || grep -qE "\bscanf\s*\(\s*\"%s\"" "$src"; then
            echo -e "\033[0;31m[SECURITY VIOLATION] Compilation Blocked (Buffer Overflow Vulnerability)!\033[0m" >&2
            echo -e "\033[0;33mUnsafe memory function detected in '$src'. Use bounds-checked alternatives.\033[0m" >&2
            exit 1
        fi

        # --- VECTOR B: Check-to-Act ---
        if grep -qE "(stat|lstat|access|euidaccess)\s*\(" "$src"; then
            if grep -qE "(open|fopen|chmod|chown|unlink|rename)\s*\(" "$src"; then
                if ! grep -qE "(fstat|fchmod|fchown|openat|O_NOFOLLOW)" "$src"; then
                    echo -e "\033[0;31m[SECURITY VIOLATION] Compilation Blocked (Filesystem Check-to-Use Race Condition)!\033[0m" >&2
                    echo -e "\033[0;33mUnsafe Check-to-Act pattern in '$src': Path checks combined with file operations without file descriptors.\033[0m" >&2
                    exit 1
                fi
            fi
        fi

        # --- VECTOR C: Insecure Temporary File Races ---
        if grep -qE "\b(tmpnam|tempnam|mktemp)\s*\(" "$src"; then
            echo -e "\033[0;31m[SECURITY VIOLATION] Compilation Blocked (Insecure Tempfile Race)!\033[0m" >&2
            echo -e "\033[0;33mDeprecated temporary file function used in '$src'. Use mkstemp() instead.\033[0m" >&2
            exit 1
        fi

        # --- VECTOR D: Multithreading Detection ---
        if grep -qE "#include\s*<(thread|pthread\.h)>" "$src"; then
            HAS_MULTITHREADING=true
        fi
    fi
done

# PART 2: Universal Multi-Language Script Scanning (Space-Safe via while-read)
while IFS= read -r py_file; do
    [ -z "$py_file" ] && continue
    if grep -qE "os\.path\.exists\s*\(" "$py_file" && grep -qE "open\s*\(" "$py_file"; then
        echo -e "\033[0;31m[SECURITY VIOLATION] Workspace Scan Blocked (Python Check-to-Use Race in '$py_file')!\033[0m" >&2
        exit 1
    fi
done < <(find . -maxdepth 3 -name "*.py" 2>/dev/null)

while IFS= read -r php_file; do
    [ -z "$php_file" ] && continue
    if grep -qE "(file_exists|is_writable)\s*\(" "$php_file" && grep -qE "(fopen|file_put_contents)\s*\(" "$php_file"; then
        echo -e "\033[0;31m[SECURITY VIOLATION] Workspace Scan Blocked (PHP Check-to-Use Race in '$php_file')!\033[0m" >&2
        exit 1
    fi
done < <(find . -maxdepth 3 -name "*.php" 2>/dev/null)

# PART 3: Automated Hardening & Compilation Execution
INJECTION_FLAGS=(
    "-fsanitize=address" 
    "-O2" 
    "-D_FORTIFY_SOURCE=3" 
    "-fstack-protector-strong" 
    "-g"
)

# If multithreading is detected, inject ThreadSanitizer to catch data races at runtime
if [ "$HAS_MULTITHREADING" = true ]; then
    INJECTION_FLAGS+=("-fsanitize=thread")
    echo -e "\033[0;35m[INFO] Multi-threading detected. Injecting ThreadSanitizer (-fsanitize=thread).\033[0m" >&2
fi

# Pass through execution with mandatory defenses injected
exec /usr/bin/g++ "${INJECTION_FLAGS[@]}" "$@"
EOF

chmod +x "$WRAPPER_PATH"
echo -e "\033[0;32m[+] Hardened Universal Security Enforcer installed successfully at $WRAPPER_PATH.\033[0m"