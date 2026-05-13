#!/bin/bash
# publish.sh - cherry-pick commits from personal/main to origin/main
#
# Usage:
#   ./publish.sh                   publish the latest commit
#   ./publish.sh <hash>            publish a specific commit
#   ./publish.sh <hash1> <hash2>   publish a range (hash1 is older, hash2 is newer)

set -e

ORIGIN="origin"
PERSONAL="personal"
BRANCH="main"
TEMP="pub-temp"

# resolve what to cherry-pick
if [ $# -eq 0 ]; then
    COMMITS=$(git rev-parse HEAD)
    echo "Publishing latest commit: $(git log --oneline -1)"
elif [ $# -eq 1 ]; then
    COMMITS=$1
    echo "Publishing commit: $(git log --oneline -1 $1)"
elif [ $# -eq 2 ]; then
    COMMITS=$(git log --oneline $1..$2 --reverse | awk '{print $1}')
    echo "Publishing range $1..$2:"
    git log --oneline $1..$2 --reverse
else
    echo "Usage: ./publish.sh [hash] [hash2]"
    exit 1
fi

echo ""

# confirm
read -p "Push to $ORIGIN/$BRANCH? (y/n): " CONFIRM
if [ "$CONFIRM" != "y" ]; then
    echo "Aborted."
    exit 0
fi

echo ""

# fetch latest origin state
echo "Fetching $ORIGIN..."
git fetch $ORIGIN

# create temp branch from origin/main
git checkout -b $TEMP $ORIGIN/$BRANCH

# cherry-pick the commits
echo "Cherry-picking..."
for HASH in $COMMITS; do
    git cherry-pick $HASH
done

# push to origin/main
echo "Pushing to $ORIGIN/$BRANCH..."
git push $ORIGIN $TEMP:$BRANCH

# clean up
git checkout $BRANCH
git branch -D $TEMP

echo ""
echo "Done. Published to $ORIGIN/$BRANCH."
