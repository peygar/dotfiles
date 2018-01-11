#!/bin/bash

BACKUP_ROOT="/Users/Peyman/Library/DotFiles/src"

# oh my zsh
cp ~/.zshrc $BACKUP_ROOT/zsh/
cp ~/.oh-my-zsh/themes/dracula.zsh-theme $BACKUP_ROOT/zsh/
cp -r ~/.oh-my-zsh/custom $BACKUP_ROOT/zsh/
cp -r ~/.bin $BACKUP_ROOT/zsh/

# iterm
cp -r ~/Library/Application\ Support/iTerm2/Configuration $BACKUP_ROOT/iterm/

# sublime
cp -r "/Users/Peyman/Library/Application Support/Sublime Text 3" $BACKUP_ROOT/
