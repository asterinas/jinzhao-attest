#!/usr/bin/env bash

CURRENTDIR="$(readlink -f $(pwd))"
SCRIPTNAME=$(basename $0)
ARG_ITEMS="$@"

CLANG_WHITE_LIST_FILE=".clang-white-list"
CLANG_BLACK_LIST_FILE=".clang-black-list"

show_help() {
    echo "Usage $SCRIPTNAME dir1/file1 [dir2/file2 [...]]"
}

get_items() {
    local current_dir="$1" 
    local specified_items="$2" # specifed items
    local current_white_list=$current_dir/$CLANG_WHITE_LIST_FILE
    local whitelist_items=""
    local current_items=""

    if [ -n "$specified_items" ] ; then
        # If there are specied items, return it directly
        current_items="$specified_items"
    elif [ -e "$current_white_list" ] ; then
        # Process items in the white list file only if it exists
        whitelist_items="$(cat $current_white_list | xargs)"
        for i in $whitelist_items ; do
            current_items="$current_items $current_dir/$i"
        done
    elif [ -z "$current_items" ] ; then
        # Process current directory if there are no specified items and white list
        #current_dir="$(readlink -f $current_dir)"
        # add files in currrent directory
        for f in $(find $current_dir -maxdepth 1 -type f -iname "*.h" -o -iname "*.cpp" -o -iname "*.cc") ; do
            current_items="$current_items $f"
        done
        # add directories in current directory
        for d in $(find $current_dir -maxdepth 1 -type d) ; do
            # ignore ./ in find result
            [ "$d" == "$current_dir" ] && continue
            current_items="$current_items $d"
        done
    fi

    echo "$current_items"
    return 0
}

update_excludes() {
    local current_dir="$1" 
    local current_excludes=""
    local current_black_list=$current_dir/$CLANG_BLACK_LIST_FILE

    # Check the black list
    if [ -e "$current_black_list" ] ; then
        current_excludes="$(cat $current_black_list | xargs)"
    fi

    # Append the excludes patterns
    for i in $current_excludes ; do
        EXCLUDES="$EXCLUDES $current_dir/$i"
    done
}

check_exclude() {
    local item_name=$1

    # ignore file which matchs the pattern the black list
    for i in $EXCLUDES ; do
        echo "$item_name" | grep -q "$i" && return 0
    done
    return 1
}

process_file() {
    local filename=$1

    check_exclude $filename && return 0

    if echo "$filename" | grep -q -E ".*\.cpp|.*\.cc|.*\.h" ; then
        echo "[FORMAT] $filename"
        [ "$DRYRUN" == "1" ] && return 0
        clang-format -style=file -i $1
    else
        echo "[IGNORE] Not C++ source or header file: $filename"
    fi
}

process_dir() {
    local dirname="$1"
    local specified_items="$2" # maybe empty
    local items=""

    # The updated excludes will also impact process_file
    update_excludes $dirname

    # Check whether need to ignore this directory
    check_exclude $dirname && return 0

    # Only print directory when dry run debug
    [ "$DRYRUN" == "1" ] && echo "----[DIRECTORY] $dirname"

    # process items
    items="$(get_items $dirname $specified_items)"
    for item in $items ; do
        if [ -f "$item" ] ; then
            process_file $item
        elif [ -d "$item" ] ; then
            process_dir $item
        else
            echo "[IGNORE] Not file or directory: $item"
        fi
    done
}

# Main Start
[ "$1" == "-h" -o "$1" == "--help" ] && show_help && exit 0
process_dir "." "$ARG_ITEMS"
echo "====================================================="
echo "Done processing all files!"
exit 0
