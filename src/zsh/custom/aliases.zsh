################## Aliases ##################

### General ###
# alias potato="ssh -Y $STUDENT_ENV -q -i ~/.ssh/linux_rsa"
alias potato2="ssh -Y $STUDENT_ENV002 -q -i ~/.ssh/linux_rsa"
alias reload="source ~/.zshrc"
alias g++="g++ -Wall -std=c++11"
alias calc="bc -l $ZSH/custom/.bc-startup"
alias execmod="chmod u+x"
alias fb="fb-messenger-cli"
alias spot='/usr/local/bin/spotify'

### Config ###
alias confzsh="st ~/.zshrc"
alias confalias="st ~/.oh-my-zsh/custom/aliases.zsh"
alias confkeys="st ~/.oh-my-zsh/custom/keybindings.zsh"
alias confsstudent="st ~/.oh-my-zsh/custom/student-env.zsh"

### Navigation ###
alias gowwn="~/Documents/waterlooworks-now"
alias godoc="~/Documents"
alias gosublime='$SUBL'
alias goohmyzsh='$ZSH'
alias gochartie="~/Documents/chartie3/"

### Git ###
alias gcob="git checkout -b"
alias ggpushu="ggpush -u"

### Troll ###
alias ayy="echo lmao"

### Functions ###
# curl image and print
function imgcurl() {
    curl $1 | imgcat
}

# fzf search through history
function fh() {
  eval $( ([ -n "$ZSH_NAME" ] && fc -l 1 || history) | fzf +s --tac | sed 's/ *[0-9]* *//')
}
