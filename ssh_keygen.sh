#!/bin/bash

DEFAULT_KEYPATH="/home/$USER/.ssh/id_rsa"

read -p "Enter your email: " email
file="hi"
read -p "Enter a file in which to save the key (/home/you/.ssh/id_rsa): [Press enter] " keypath

if [[ $keypath -eq "" ]]; then
    keypath=$DEFAULT_KEYPATH
fi

ssh-keygen -t rsa -b 4096 -C $email -f $keypath

eval "$(ssh-agent -s)"

ssh-add $keypath

# TODO: github

read -p "Enter server hostname: " server_host
read -p "Enter server username: " server_username
read -p "Give a friendly name for your server: " server_friendly

publickey=`cat "$keypath.pub"`

ssh "$server_username@$server_host" "touch ~/.ssh/authorized_keys && echo $publickey >> ~/.ssh/authorized_keys"

touch ~/.ssh/config
echo "" >>  ~/.ssh/config
echo "Host $server_friendly
    User $server_username
    Hostname $server_host
    PubkeyAuthentication yes
    IdentityFile $keypath
    ForwardAgent yes
" >> ~/.ssh/config

