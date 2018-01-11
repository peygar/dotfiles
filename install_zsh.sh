sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

cp ./src/zsh/.zshrc ~/.zshrc
cp ./src/zsh/dracula.zsh-theme ~/.oh-my-zsh/themes/dracula.zsh-theme
cp -r ./src/zsh/custom ~/.oh-my-zsh/custom
cp -r ./src/zsh/.bin ~/.bin
cp ./src/zsh/.iterm2_shell_integration.zsh ~/
