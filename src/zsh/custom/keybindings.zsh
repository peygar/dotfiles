# binds hex 0x18 0x7f with deleting everything to the left of the cursor
bindkey "^X\\x7f" backward-kill-line
bindkey "^X\\x66" history-incremental-search-backward

# hightlight text with shift + arrow keys. Also adds ablitiy
# to delete and copy ect.
r-delregion() {
    if ((REGION_ACTIVE)) then
       zle kill-region
    else
       zle $1
    fi
}

r-deselect() {
    ((REGION_ACTIVE = 0))
    zle $1
}

r-select() {
  ((REGION_ACTIVE)) || zle set-mark-command
  zle $1
}

for key kcap seq mode widget (
    sleft   kLFT    $'\e[1;2D' select backward-char
    sright  kRIT    $'\e[1;2C' select forward-char
    sup     kri     $'\e[1;2A' select beginning-of-line
    sdown   kind    $'\e[1;2B' select end-of-line

    left    kcub1   $'\EOD' deselect backward-char
    right   kcuf1   $'\EOC' deselect forward-char

    asleft  x       $'\e[1;10D' select backward-word
    asright x       $'\e[1;10C' select forward-word

    aleft  x       $'\eb' deselect backward-word
    aright x       $'\ef' deselect forward-word

    cleft   x       $'\E[1;5D'   deselect backward-word
    cright  x       $'\E[1;5C'   deselect forward-word

    del     kdch1   $'\E[3~' delregion delete-char
    bs      x       $'^?' delregion backward-delete-char

  ) {
    eval "key-$key() r-$mode $widget"
    zle -N key-$key
    bindkey ${terminfo[$kcap]-$seq} key-$key
}
