#!/bin/bash
# State manager for hookify blocking hooks
# Tracks whether required actions (code-simplifier, pr-review) were completed

# Check for required dependencies
if ! command -v jq &> /dev/null; then
    echo "Warning: jq not installed, state management disabled" >&2
    exit 0  # Allow operation to continue
fi

STATE_DIR="${CLAUDE_PROJECT_ROOT:-.}/.claude/state"
MAX_AGE_MINUTES=30

# Ensure state directory exists
mkdir -p "$STATE_DIR"

usage() {
    echo "Usage: $0 <command> <action-name> [files...]"
    echo ""
    echo "Commands:"
    echo "  mark <action> [files...]  - Mark action as completed for files"
    echo "  check <action>            - Check if action was completed (exit 0=yes, 1=no)"
    echo "  clear <action>            - Clear the state for an action"
    echo "  clear-all                 - Clear all state files"
    echo ""
    echo "Actions: code-simplifier, pr-review"
    exit 1
}

get_state_file() {
    echo "$STATE_DIR/$1.json"
}

# Mark an action as completed
mark_completed() {
    local action="$1"
    shift
    local files=("$@")
    local state_file=$(get_state_file "$action")
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Get staged files if no files provided
    if [ ${#files[@]} -eq 0 ]; then
        mapfile -t files < <(git diff --cached --name-only 2>/dev/null)
    fi

    # Create JSON
    local files_json=$(printf '%s\n' "${files[@]}" | jq -R . | jq -s .)

    cat > "$state_file" << EOF
{
  "action": "$action",
  "timestamp": "$timestamp",
  "files": $files_json,
  "git_head": "$(git rev-parse HEAD 2>/dev/null || echo 'unknown')"
}
EOF

    echo "Marked $action as completed at $timestamp"
}

# Check if action was completed recently
check_completed() {
    local action="$1"
    local state_file=$(get_state_file "$action")

    # Check if state file exists
    if [ ! -f "$state_file" ]; then
        echo "NOT_FOUND: No state file for $action"
        return 1
    fi

    # Check age
    local timestamp=$(jq -r '.timestamp' "$state_file")
    local state_epoch=$(date -d "$timestamp" +%s 2>/dev/null || echo 0)
    local now_epoch=$(date +%s)
    local age_minutes=$(( (now_epoch - state_epoch) / 60 ))

    if [ $age_minutes -gt $MAX_AGE_MINUTES ]; then
        echo "EXPIRED: $action was run $age_minutes minutes ago (max: $MAX_AGE_MINUTES)"
        return 1
    fi

    # Check if staged files match (for commit hook)
    if [ "$action" = "code-simplifier" ]; then
        local staged_files=$(git diff --cached --name-only 2>/dev/null | sort)
        local reviewed_files=$(jq -r '.files[]' "$state_file" 2>/dev/null | sort)

        # Skip file comparison if no staged files or no reviewed files
        if [ -z "$staged_files" ]; then
            echo "OK: No staged files to check"
            return 0
        fi

        # If reviewed_files is empty but staged_files is not, files weren't reviewed
        if [ -z "$reviewed_files" ]; then
            echo "MISMATCH: Staged files exist but no reviewed files recorded"
            return 1
        fi

        # Allow if reviewed files is a superset of staged files
        # Use process substitution with explicit newline handling to avoid comm errors
        local missing=$(comm -23 <(echo "$staged_files" | grep -v '^$') <(echo "$reviewed_files" | grep -v '^$') 2>/dev/null || echo "")
        if [ -n "$missing" ]; then
            echo "MISMATCH: These staged files were not reviewed: $missing"
            return 1
        fi
    fi

    echo "OK: $action completed $age_minutes minutes ago"
    return 0
}

# Clear state for an action
clear_state() {
    local action="$1"
    local state_file=$(get_state_file "$action")

    if [ -f "$state_file" ]; then
        rm "$state_file"
        echo "Cleared state for $action"
    else
        echo "No state to clear for $action"
    fi
}

# Clear all state
clear_all() {
    rm -f "$STATE_DIR"/*.json 2>/dev/null
    echo "Cleared all state files"
}

# Main
case "${1:-}" in
    mark)
        [ -z "${2:-}" ] && usage
        mark_completed "$2" "${@:3}"
        ;;
    check)
        [ -z "${2:-}" ] && usage
        check_completed "$2"
        ;;
    clear)
        [ -z "${2:-}" ] && usage
        clear_state "$2"
        ;;
    clear-all)
        clear_all
        ;;
    *)
        usage
        ;;
esac
