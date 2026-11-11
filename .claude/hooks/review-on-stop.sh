#!/usr/bin/env bash
set -euo pipefail

[[ -n "${CII_REVIEW_HOOK:-}" ]] && exit 0

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

state_dir=.claude/review-state
mkdir -p "$state_dir"
max_rounds="${CII_REVIEW_MAX_ROUNDS:-12}"

allow() {
  if [[ -n "${1:-}" ]]; then
    jq -n --arg m "$1" '{systemMessage: $m}'
  fi
  exit 0
}

command -v jq >/dev/null || {
  echo '{"systemMessage": "review hook: jq not found, review skipped"}'
  exit 0
}
command -v claude >/dev/null || allow "review hook: claude CLI not found, review skipped"

pathspec=('*.go' 'go.mod' 'go.sum' 'Makefile' '*.sh' '.github/workflows/*')

if git rev-parse -q --verify origin/main >/dev/null; then
  base=$(git merge-base HEAD origin/main)
else
  base=$(git rev-list --max-parents=0 HEAD | tail -1)
fi

diff_file="$state_dir/diff.patch"
{
  git diff "$base" -- "${pathspec[@]}"
  git ls-files --others --exclude-standard -- "${pathspec[@]}" | while IFS= read -r f; do
    git diff --no-index -- /dev/null "$f" || true
  done
} >"$diff_file"

[[ -s "$diff_file" ]] || allow

hash=$(sha256sum "$diff_file" | cut -d' ' -f1)
[[ "$(cat "$state_dir/clean" 2>/dev/null)" == "$hash" ]] && allow

rounds=$(cat "$state_dir/rounds" 2>/dev/null || echo 0)
if ((rounds >= max_rounds)); then
  echo 0 >"$state_dir/rounds"
  allow "review hook: $max_rounds review rounds without a clean result, stopping anyway"
fi

prompt=$(cat .claude/hooks/review-prompt.md)
out=$(CII_REVIEW_HOOK=1 claude -p "$prompt

The diff under review is in $diff_file (base $base, plus untracked files)." \
  --settings '{"disableAllHooks": true}' \
  --allowedTools "Read" "Grep" "Glob" "Bash(go build *)" "Bash(go vet *)" "Bash(go test *)" "Bash(gofmt *)" "Bash(git diff *)" "Bash(git log *)" "Bash(git show *)" \
  --disallowedTools "Agent" "Task" "Workflow" \
  --output-format text 2>&1) || allow "review hook: reviewer failed to run, review skipped"

verdict=$(printf '%s\n' "$out" | grep -Eo 'VERDICT: (CLEAN|ISSUES)' | tail -1 || true)
case "$verdict" in
  "VERDICT: CLEAN")
    echo "$hash" >"$state_dir/clean"
    echo 0 >"$state_dir/rounds"
    allow "review hook: reviewer found no code issues"
    ;;
  "VERDICT: ISSUES")
    echo $((rounds + 1)) >"$state_dir/rounds"
    jq -n --arg r "Code review subagent (round $((rounds + 1))/$max_rounds) found issues. Fix the code ones (verify each first; reject false positives with a short reason in your reply), then finish again to trigger the next review round.

$out" '{decision: "block", reason: $r}'
    ;;
  *)
    allow "review hook: reviewer returned no verdict, review skipped"
    ;;
esac
