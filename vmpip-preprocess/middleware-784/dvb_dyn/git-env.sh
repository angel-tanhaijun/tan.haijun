#!/usr/bin/env bash
#  Filename: /root/.bin/git-env.sh
#   Created: 2014-07-30 17:07:06
#      Desc: get git info
# set -x
 
get_gitenv ()
{
    cd $proj_root_dir
 
    local gbranch=$(git branch | grep \* | awk '{print $2}')
    local gversion=$(git log --abbrev-commit | head -1 | awk '{print $2}')
    local gclean=$([[ `git status 2> /dev/null | tail -n1 \
                      | awk '{print $1, $2, $3}'` \
                      == "nothing to commit," ]] \
                      && echo "CLEAN" || echo "DIRTY")
    local gpushed=""
    if [[ -f "$proj_root_dir/.git/refs/remotes/origin/${gbranch}" ]]; then
        gpushed=$([[ `git log  | head -1 | awk '{print $2}'` \
        == `cat $proj_root_dir/.git/refs/remotes/origin/${gbranch}` ]] \
        && echo "-PUSHED" || echo "-NOPUSH")
    fi
     
    GIT_ENV_VERSION=${gbranch}-${gversion}-${gclean}${gpushed}

	return 0
}
 
judge_gitcommit ()
{
    cd $proj_root_dir
 
    if [[ $(git log 2>/dev/null |head -1|awk '{print $1}') == "commit" ]]; then
        gitcommit="YES"
		return 0
    else
        gitcommit=""
		return 1
    fi

}
 
proj_root_dir=`git rev-parse --show-toplevel 2>/dev/null`
[[ ! -z $proj_root_dir ]] && judge_gitcommit || { echo "NO_VERSION" && exit 1; }
[[ ! -z $gitcommit ]]     && get_gitenv      || { echo "NO_VERSION" && exit 1; }
 
echo "$GIT_ENV_VERSION"
