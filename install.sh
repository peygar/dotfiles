
# oh my zsh zsh
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

cp ./src/zsh/.zshrc ~/.zshrc
cp ./src/zsh/.oh-my-zsh/themes/dracula.zsh-theme ~/.oh-my-zsh/themes/dracula.zsh-theme
cp -r ./src/zsh/.oh-my-zsh/custom ~/.oh-my-zsh/custom
cp -r ./src/zsh/.bin ~/.bin

# iterm
mkdir ~/Library/Application\ Support/iTerm2/Configuration
cp -r ./src/iterm/Configuration ~/Library/Application\ Support/iTerm2/Configuration
echo "Go to iterm2 and put '~/Library/Application\ Support/iTerm2/Configuration' in preferences custom folder"

# sublime
cp -r ./src/Sublime\ Text\ 3 "~/Library/Application Support/Sublime Text 3"
