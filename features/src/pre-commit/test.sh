cmd_base="$1"
version_flag="--version"

version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }

while IFS= read -r -d '' cmd_path; do
    cmd=$(basename "$cmd_path")
    [[ $cmd =~ ^$cmd_base[0-9]+(\.[0-9]+)*$ ]] || continue
    
    if version=$(timeout 2s "$cmd" "$version_flag" 2>&1 | grep -o '[0-9]\+\.[0-9]\+\.[0-9]\+'); then
        if [ -z "${HIGHEST_VERSION:-}" ] || version_gt "$version" "$HIGHEST_VERSION"; then
            HIGHEST_VERSION="$version"
            HIGHEST_CMD="$cmd"
        elif [ "$version" = "$HIGHEST_VERSION" ]; then
            HIGHEST_CMD="$cmd"
        fi
    fi
done < <(find ${PATH//:/ } -maxdepth 1 -executable -name "$cmd_base*" -print0 2>/dev/null)

if [ -n "${HIGHEST_VERSION:-}" ]; then
    printf '%s\t%s\n' "$HIGHEST_CMD" "$HIGHEST_VERSION"
fi
