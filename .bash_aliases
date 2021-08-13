# reload bashrc after changes
#$ source .bash_aliases #better
alias rbash=source ~/.bash_aliases
#or
#$ source ~/.bashrc
# $ source ~/.bash_aliases

# ---Must be in  ~/.bashrc ---
#if [ -f ~/.bash_aliases ]; then
#. ~/.bash_aliases
#fi
#--end--

# git install bash_aliases
# wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/bash_aliases/main/.bash_aliases

alias sai=apt install -y

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
alias ta='tmux attach-session -t '
alias tk='tmux kill-session -t '
alias tn='tmux new -s '
alias tl='tmux list-session'

#alias update='sudo -- sh -c "/root/bin/chk_disk && dnf update'

#restore tmux session even after reboot
alias mux='pgrep -vx tmux > /dev/null && \
		tmux new -d -s delete-me && \
		tmux run-shell ~/.tmux/plugins/tmux-resurrect/scripts/restore.sh && \
		tmux kill-session -t delete-me && \
		tmux attach || tmux attach'

# debian update system
alias dup='sudo apt clean && apt-get update && apt-get upgrade && apt-get dist-upgrade'

#toggle between the last two directories
alias -="cd -"
