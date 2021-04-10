# reload bashrc after changes
#$ source .bash_aliases #better
#or
#$ source ~/.bashrc
# $ source ~/.bash_aliases

# ---Must be in  ~/.bashrc ---
#if [ -f ~/.bash_aliases ]; then
#. ~/.bash_aliases
#fi
#--end--

# git install bash_aliases
# $ wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/tmux.conf/master/.bash_aliases

alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."
alias ......="cd ../../../../.."

alias g=git
alias gita="git add -A ."
alias gitc="git commit -m"
alias gitp="git push"
alias gits="git status"

alias la="ls -la"
alias lll="ls -all | less"
alias lt="ls --tree"

# Lock the screen (when going AFK)
alias afk="/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend"

alias sstatus="sudo systemctl status -l"
alias srestart="sudo systemctl restart"

# tmux
alias t='tmux'
alias ta='tmux attach -t '
alias tn='tmux new -s '

#alias update='sudo -- sh -c "/root/bin/chk_disk && dnf update'

