sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"

cp ./src/zsh/.zshrc ~/.zshrc
cp ./src/zsh/.oh-my-zsh/themes/dracula.zsh-theme ~/.oh-my-zsh/themes/dracula.zsh-theme
cp -r ./src/zsh/.oh-my-zsh/custom ~/.oh-my-zsh/custom
cp -r ./src/zsh/.bin ~/.bin
