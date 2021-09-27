#!/usr/bin/env bash
# skip-terminology-file-check
set -eo pipefail

cat "$GITHUB_EVENT_PATH"

PR_BASE_SHA=$(jq -r '.pull_request.base.sha' "$GITHUB_EVENT_PATH")
BEFORE=$(jq -r '.before' "$GITHUB_EVENT_PATH")
if [[ $PR_BASE_SHA != "" && $PR_BASE_SHA != "null" ]]; then # PR events
    SHA=$PR_BASE_SHA
elif [[ $BEFORE != "" && $BEFORE != "null" ]]; then # push events
    SHA=$BEFORE
else
    echo "This does not appear to be a PR or a push event"
    echo "Setting 'has_offensive_words' to 'no'"
    echo "::set-output name=has_offensive_words::no"
    exit 0
fi
echo "BASE SHA: $SHA"

rootpath=$(git rev-parse --show-toplevel)
files=($(git diff "$SHA" HEAD --name-only))

files_need_check=""
for f in "${files[@]}";
do
  set +e
  grep 'skip-terminology-file-check' $rootpath"/"$f
  if [ $? -ne 0 ];then
    files_need_check="$files_need_check $f"
  fi
  set -e
done

result=false
files_need_check_arr=($files_need_check)
for file in "${files_need_check_arr[@]}";
do
  set +e
  git diff "$SHA" HEAD $file > diffcontent
  # check new added content only
  cat diffcontent | grep '^+' | grep -w 'kill\|whitelist\|blacklist\|blackout\|brownout\|master\|slave\|segregate\|segregation' --binary-files=without-match
  if [ $? -eq 0 ];then
    echo "================"
    echo "found offensive words in $file"
    result=true
  fi
  set -e
done

if $result;then
  echo "::set-output name=has_offensive_words::yes"
  exit 0
fi
