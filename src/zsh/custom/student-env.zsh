# copy files from local directory to mapped directory in the student env
function csup() {
    DIR="$(pwd)"
    TARGET="~/cs${DIR##*Documents/CS}"
    echo "Moving file(s) $* to ${STUDENT_ENV}:${TARGET}"
    scp -r -i ~/.ssh/linux_rsa $* "${STUDENT_ENV}:${TARGET}"
}

# copy file from mapped directory in the student env to local directory
function csdown() {
    DIR="$(pwd)"
    TARGET="~/cs${DIR##*Documents/CS}/$1"
    echo "Copying file from ${STUDENT_ENV}:${TARGET}"
    scp -r -i ~/.ssh/linux_rsa "${STUDENT_ENV}:${TARGET}" .
}

# remove file from local directory and mapped student env copy
function csrm() {
    DIR="$(pwd)"
    TARGET_DIR="~/cs${DIR##*Documents/CS}"
    echo "removing local copy"
    rm $*
    echo "removing remote copy"
    ssh -i ~/.ssh/linux_rsa $STUDENT_ENV "cd $TARGET_DIR; rm -r $*"
}

# copy file from student env and open in sublime
function csst() {
    DIR="$(pwd)"
    TARGET="~/cs${DIR##*Documents/CS}/$1"
    echo "Copying file from ${STUDENT_ENV}:${TARGET}"
    scp -r -i ~/.ssh/linux_rsa "${STUDENT_ENV}:${TARGET}" .
    st $1
}

# log into student env and cd to mapped directory
function potato() {
    if [ -n "$1" ]; then
        re='^[0-9]+$'
        if [[ $1 =~ $re ]] ; then
            REMOTE="pgardide@ubuntu1604-00${1}.student.cs.uwaterloo.ca"
            shift
        fi
    else
        REMOTE=$STUDENT_ENV
    fi
    DIR="$(pwd)"
    OPTS="-t -i ~/.ssh/linux_rsa"
    if [[ "$DIR" == *"/Documents/CS"* ]]; then
        TARGET="~/cs${DIR##*Documents/CS}"
        ssh $(echo $OPTS $*) $REMOTE "cd ${TARGET}; zsh"
    else
        ssh $(echo $OPTS $*) $REMOTE "zsh"
    fi
}
