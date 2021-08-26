#reload bashrc after changes
#source .bashrc or ralias

#or
#$ source ~/.bashrc
# $ source ~/.bash_aliases

## ---Must be in  ~/.bashrc ---
#if [ -f ~/.bash_aliases ]; then
#. ~/.bash_aliases
#fi
#--end--

# git install bash_aliases
# wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/bash_aliases/main/.bash_aliases
alias updatealias="wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/bash_aliases/main/.bash_aliases"
alias rass="source ~/.bashrc"

#apt install, just add package ie $sai ufw
alias sai="sudo apt install -y"

# become root #
alias root='sudo -i'
alias su='sudo -i'

alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."
alias ......="cd ../../../../.."

#ansible
alias Ap="ansible-playbook"

#progress bar on file copy. Useful evenlocal.
alias cpProgress="rsync --progress -ravz"

#docker
alias testdocker="docker run hello-world"
alias dockershell="docker run --rm -i -t --entrypoint=/bin/bash"
alias dockershellsh="docker run --rm -i -t --entrypoint=/bin/sh"
alias impacket="docker run --rm -it rflathers/impacket"
alias metasploit="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" metasploitframework/metasploit-framework ./msfconsole"
alias metasploitports="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework ./msfconsole"
alias msfvenomhere="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -v "${PWD}:/data" metasploitframework/metasploit-framework ./msfvenom"
alias postfiledumphere="docker run --rm -it -p80:3000 -v "${PWD}:/data" rflathers/postfiledump"
alias reqdump="docker run --rm -it -p 80:3000 rflathers/reqdump"
alias pwncat="docker build -t pwncat ."
#docker pull resilio/sync
alias sync="docker run -d --name Sync -p 127.0.0.1:$WEBUI_PORT:8888 -p 55555 -v $DATA_FOLDER:/mnt/sync --restart on-failure resilio/sync"
alias Di"docker images"
alias Dl="docker login" 
alias Dps="docker ps" 
alias Ds="docker start"
alias Dv="docker --version"

#git
alias g=git
alias gita="git add -A ."
alias gitc="git commit -m"
alias gitp="git push"
alias gits="git status"

alias laa="ls -la"
alias lll="ls -all | less"
alias lt="ls --tree"

#IP
alias ip="dig +short myip.opendns.com @resolver1.opendns.com"
alias network.connections='sudo lsof -l -i +L -R -V'
alias network.established='sudo lsof -l -i +L -R -V | grep ESTABLISHED'
alias network.externalip='curl -s http://checkip.dyndns.org/ | sed "s/[a-zA-Z<>/ :]//g"'

# display all rules #
alias iptlist='sudo /sbin/iptables -L -n -v --line-numbers'
alias iptlistin='sudo /sbin/iptables -L INPUT -n -v --line-numbers'
alias iptlistout='sudo /sbin/iptables -L OUTPUT -n -v --line-numbers'
alias iptlistfw='sudo /sbin/iptables -L FORWORD -n -v --line-numbers'
alias firewall=iptlist

#Test internet speed
alias netspeed="curl -L https://github.com/ddo/fast/releases/download/v0.0.4/fast_linux_amd64 -o fast && wget https://github.com/ddo/fast/releases/download/v0.0.4/fast_linux_amd64 -O fast"


# Lock the screen (when going AFK)
alias afk="/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend"

#alias LetsHack=sudo systemctl start openvpn && sudo openvpn /thm/yourvpn-profile.ovpn
#alias LetsHackthebox=sudo systemctl start openvpn && sudo openvpn /thm/yourvpn-profile.ovpn


#python virtual environments ansible
alias vansible4="source ansible4.0/bin/activate"
#alias vansible="cd ~/python-venv && source ansible4.0/bin/activate && cd ~/ansible"
alias vansible="cd ~/python_virtualenv/vansible/vansible4.0/ && source bin/activate && cd ~/ansible"


alias sstatus="sudo systemctl status -l"
alias srestart="sudo systemctl restart"


# tmux
alias t="tmux"
alias ta="tmux attach-session -t "
alias tk="tmux kill-session -t "
alias tn="tmux new -s "
alias tl="tmux list-session"

#restore tmux session even after reboot
alias mux="pgrep -vx tmux > /dev/null && \
		tmux new -d -s delete-me && \
		tmux run-shell ~/.tmux/plugins/tmux-resurrect/scripts/restore.sh && \
		tmux kill-session -t delete-me && \
		tmux attach || tmux attach"


# debian update system
alias dup="sudo apt clean && apt-get update && apt-get upgrade && apt-get dist-upgrade"
alias update="sudo --sh -c '/root/bin/chk_disk && dnf update'"

#check ports open
alias whatisopen="sudo lsof -i && sudo nmap -p- -sU -sS --open 127.0.0.1"

#toggle between the last two directories
#alias -="cd -"

#add date stamp to bash history
export HISTTIMEFORMAT="%F %T"


#weather
alias weather="curl wttr.in/"
#weather toronto

#-c flag in order to continue the download in case of problems
alias wget="wget -c"
alias h=history

#Red Team 
export AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36" 
alias curl="curl -A '$AGENT'" 
alias wget="wget -U '$AGENT'" 
alias nmap="nmap --script-args=\"http.useragent='$AGENT' \""

#find the files that has been added/modified most recently:
alias lt="ls -alrt"

# file tree of current directory
alias tree="find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'"

#Functions:
function dockershell() {
    docker run --rm -i -t --entrypoint=/bin/bash "$@"
}

function dockershellsh() {
    docker run --rm -i -t --entrypoint=/bin/sh "$@"
}

function dockershellhere() {
    dirname=${PWD##*/}
    docker run --rm -it --entrypoint=/bin/bash -v `pwd`:/${dirname} -w /${dirname} "$@"
}

function dockershellshhere() {
    docker run --rm -it --entrypoint=/bin/sh -v `pwd`:/${dirname} -w /${dirname} "$@"
}

function dockerwindowshellhere() {
    dirname=${PWD##*/}
    docker -c 2019-box run --rm -it -v "C:${PWD}:C:/source" -w "C:/source" "$@"
}
#getting error?
function impacket() {
    docker run --rm -it rflathers/impacket "$@"
}

function smbservehere() {
    local sharename
    [[ -z $1 ]] && sharename="SHARE" || sharename=$1
    docker run --rm -it -p 445:445 -v "${PWD}:/tmp/serve" rflathers/impacket smbserver.py -smb2support $sharename /tmp/serve
}

nginxhere() {
    docker run --rm -it -p 80:80 -p 443:443 -v "${PWD}:/srv/data" rflathers/nginxserve
}

webdavhere() {
    docker run --rm -it -p 80:80 -v "${PWD}:/srv/data/share" rflathers/webdav
}

    docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" metasploitframework/metasploit-framework ./msfconsole "$@"
}

metasploitports() {
    docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework ./msfconsole "$@"
}

msfvenomhere() {
    docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -v "${PWD}:/data" metasploitframework/metasploit-framework ./msfvenom "$@"
}

reqdump() {
    docker run --rm -it -p 80:3000 rflathers/reqdump
}

postfiledumphere() {
    docker run --rm -it -p80:3000 -v "${PWD}:/data" rflathers/postfiledump
}

function msfvenom() {
    local entrydir="/usr/src/metasploit-framework"
    local image="metasploitframework/metasploit-framework:latest"
    local name="msfvenom_$(head -c 8 /dev/random | xxd -p)"

    mkdir -p "$HOME/.msf4"
    docker run -e MSF_GID=$(id -g) -e MSF_UID=$(id -u) \
        --entrypoint "$entrydir/docker/entrypoint.sh" -i \
        --name "$name" --rm -tv "$HOME/.msf4":/home/msf/.msf4 \
        -v "$(pwd)":/msf:Z -w /msf $image "$entrydir/msfvenom" "$@"
}

#shown the contents of a directory immediately after moving to it by cd DIRECTORY 
cdl()    {
  cd"$@";
  ls -al;
}
