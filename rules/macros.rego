package macros

#
# open events
#
open_write {
	open_event
	is_open_write
	input.event.params["fd"] >= 0
}

open_read {
	open_event
	is_open_read
	input.event.params["fd"] >= 0
}

open_create {
	open_event
	is_open_create
	input.event.params["fd"] >= 0
}
open_create {
	input.event.name = "creat"
}

open_event {
	input.event.name = open_syscalls[_]
}

open_syscalls := [ "open", "openat" ]

is_open_write {
	round((input.event.params.flags-0.1) / O_WRONLY) % 2 > 0
}

is_open_read {
	round((input.event.params.flags-0.1) / O_RDONLY) % 2 > 0
}

is_open_create {
	round((input.event.params.flags-0.1) / O_CREAT) % 2 > 0
}
o_trunc_flag_set {
	round((input.event.params.flags-0.1) / O_TRUNC) % 2 > 0
}

O_RDONLY := 1
O_WRONLY := 2
O_CREAT  := 4
O_TRUNC  := 256


#
# sensitive files
#
sensitive_files := [
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/pam.conf",
	"/etc/security/pwquality.conf"
]
sensitive_directory_names := [ "/", "/etc", "/etc/", "/root", "/root/" ]

#
# shell configs
#
bash_config_filenames := [ ".bashrc", ".bash_profile", ".bash_history", ".bash_login", ".bash_logout", ".inputrc", ".profile" ]
csh_config_filenames := [ ".cshrc", ".login", ".logout", ".history", ".tcshrc", ".cshdirs" ]
zsh_config_filenames := [ ".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout" ]

shell_config_filenames[name] { name := bash_config_filenames[_] }
shell_config_filenames[name] { name := csh_config_filenames[_] }
shell_config_filenames[name] { name := zsh_config_filenames[_] }

bash_config_files := [ "/etc/profile", "/etc/bashrc" ]
csh_config_files := [ "/etc/csh.cshrc", "/etc/csh.login" ]

shell_config_files[name] { name := bash_config_files[_] }
shell_config_files[name] { name := csh_config_files[_] }

shell_config_directories := [ "/etc/zsh" ]

#
# open shell config files
#
open_shell_config_files {
	name := shell_config_filenames[_]
	endswith(file, name)
}

open_shell_config_files {
	file = shell_config_files[_]
}

open_shell_config_files {
	file_inside_directory(shell_config_directories[_])
}

#
# shell process
#
shell_binaries := [ "ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash" ]

is_shell_process { input.process.name = shell_binaries[_] }

#
# cron
#
update_cron_config {
	open_write
	startswith(file, "/etc/cron")
}

start_crontab {
	spawned_process
	input.process.executable = "crontab"
}

#
# new process
#
spawned_process {
	input.event.name = "execve"
}

#
# files
#
file = filename {
	filename := input.event.params["name"]
}

file_inside_directory(dir) {
	# filename starts with directory name
	startswith(file, dir)
}

file_inside_given_directory(filename, dir) {
	startswith(filename, dir)
}

#
# modify
#
rename_syscalls := [ "rename", "renameat" ]
rename {
	input.event.name = rename_syscalls[_]
}

mkdir_syscalls := [ "mkdir", "mkdirat" ]
mkdir {
	input.event.name = mkdir_syscalls[_]
}

remove_syscalls := [ "rmdir", "unlink", "unlinkat" ]
remove {
	input.event.name = remove_syscalls[_]
}

modify {
	rename
}
modify {
	remove
}

modify_file(filename) {
	contains(input.event.params.name, filename)
}
modify_file(filename) {
	contains(input.event.params.oldpath, filename)
}
modify_file(filename) {
	contains(input.event.params.pathname, filename)
}

#
# package management binaries
#
rpm_binaries := [
	"dnf", "rpm", "rpmkey", "yum", "75-system-updat", "rhsmcertd-worke", "subscription-ma",
    "repoquery", "rpmkeys", "rpmq", "yum-cron", "yum-config-mana", "yum-debug-dump",
    "abrt-action-sav", "rpmdb_stat", "microdnf", "rhn_check", "yumdb"
]

openscap_rpm_binaries := [ "probe_rpminfo", "probe_rpmverify", "probe_rpmverifyfile", "probe_rpmverifypackage" ]

rpm_procs {
	input.process.name = rpm_binaries[_]
}
rpm_procs {
	input.process.name = openscap_rpm_binaries[_]
}
rpm_procs {
	input.process.name = "salt-minion"
}

deb_binaries := [
	"dpkg", "dpkg-preconfigu", "dpkg-reconfigur", "dpkg-divert", "apt", "apt-get", "aptitude",
    "frontend", "preinst", "add-apt-reposit", "apt-auto-remova", "apt-key",
    "apt-listchanges", "unattended-upgr", "apt-add-reposit", "apt-config", "apt-cache"
]

package_mgmt_binaries[bin] {
	bin := rpm_binaries[_]
}
package_mgmt_binaries[bin] {
	bin := deb_binaries[_]
}
package_mgmt_binaries[bin] {
    bins := [ "update-alternative", "gem", "pip", "pip3", "sane-utils.post", "alternatives", "chef-client", "apk" ]
	bin := bins[_]
}

package_management_process {
	# TODO: is it correct?
	input.process.executable = package_mgmt_binaries[_]
}

#
# update repository
#
repository_files := [ "sources.list" ]
repository_directories := ["/etc/apt/sources.list.d", "/etc/yum.repos.d" ]

access_repositories {
	endswith(file, repository_files[_])
}
access_repositories {
	file_inside_directory(repository_directories[_])
}

write_repository {
	open_write
	access_repositories
}
write_repository {
	modify
	modify_repositories
}

modify_repositories {
	# TODO: fix pathname for absolute path
	startswith(input.event.params.pathname, repository_directories[_])
}

#
# bin directories
#
bin_dirs := [ "/bin", "/sbin", "/usr/bin", "/usr/sbin" ]

bin_dir {
	file_inside_directory(bin_dirs[_])
}

#
# python
#
python_running_get_pip {
	input.process.command = "python"
	input.process.args[0] = "get-pop.py"
}
python_running_ms_oms {
	input.process.command = "python"
	input.process.args[0] = "/var/lib/waagnet/"
}

#
# docker
#
#docker_process := [ "docker", "dockerd" ]
#exe_running_docker_save {
	#startswith(input.process.cmdline, "exe /var/lib/docker")
	# TODO
	#input.process.pname is (dockerd, docker))
#}

symlink_syscalls := [ "symlink", "symlinkat" ]

create_symlink {
	input.event.name = symlink_syscalls[_]
}

symlink_target_in_sensitive_file {
	input.event.params.target = sensitive_files[_]
}
symlink_target_in_sensitive_file {
	file_inside_given_directory(input.event.params.target, sensitive_directory_names[_])
}

remote_file_copy_binaries := [ "rsync", "scp", "sftp", "dcp" ]
remote_file_copy_procs {
    input.process.name = remote_file_copy_binaries[_]
}

rename_to_hidden_file {
	rename
	contains(input.event.params.newpath, "/.")
}
mkdir_hidden_directory {
	mkdir
	contains(input.event.params.pathname, "/.")
}
create_hidden_file {
	open_write
	is_open_create
	contains(file, "/.")
	not file_inside_excluded_hidden_directory
}

exclude_hidden_directories := [ "/root/.cassandra" ]
file_inside_excluded_hidden_directory = {
	file_inside_directory(exclude_hidden_directories[_])
}

chmod_syscalls := [ "chmod", "fchmod", "fchmodat" ]

S_ISGID := 1024 #(1 << 10)
S_ISUID := 2048 #(1 << 11)

is_setuid {
	round((input.event.params.mode-0.1) / S_ISUID) % 2 > 0
}
is_setgid {
	round((input.event.params.mode-0.1) / S_ISGID) % 2 > 0
}
is_setuid_or_setgid {
	is_setuid
}
is_setuid_or_setgid {
	is_setgid
}

chmod {
	input.event.name = chmod_syscalls[_]
}

shell_history_files := [ "bash_history", "zsh_history", "fish_read_history", "fish_history" ]

delete_shell_history {
	open_write
	o_trunc_flag_set
	contains(file, shell_history_files[_])
}
rename_shell_history {
	modify
	modify_shell_history
}

modify_shell_history {
	modify_file(shell_history_files[_])
}


data_remove_process := [ "shred", "mkfs", "mke2fs" ]


log_directories := [ "/var/log", "/dev/log" ]

log_files := [ "syslog", "auth.log", "secure", "kern.log", "cron", "user.log", "dpkg.log", "last.log", "yum.log", "access_log", "mysql.log", "mysqld.log" ]

access_log_files {
	startswith(file, log_directories[_])
}
access_log_files {
	endswith(file, log_files[_])
}

# TODO
#trusted_logging_images {
#	(container.image.repository endswith "splunk/fluentd-hec")
#}

grep_binaries := [ "grep", "egrep", "fgrep" ]

grep_commands {
	input.process.command = grep_binaries[_]
}

search_private_key {
	contains(input.process.args[_], "BEGIN PRIVATE")
}
search_private_key {
	contains(input.process.args[_], "BEGIN RSA PRIVATE")
}
search_private_key {
	contains(input.process.args[_], "BEGIN DSA PRIVATE")
}
search_private_key {
	contains(input.process.args[_], "BEGIN EC PRIVATE")
}

search_password {
	contains(input.process.args[_], "pass")
}
search_password {
	contains(input.process.args[_], "ssh")
}
search_password {
	contains(input.process.args[_], "user")
}

network_tool_binaries := [ "nc", "ncat", "nmap", "dig", "tcpdump", "tshark", "ngrep" ]

network_tool_procs {
	input.process.command = network_tool_binaries[_]
}


nc_process {
	input.process.name = "nc"
	nc_with_e_or_c
}

nc_with_e_or_c {
	contains(input.process.args[_], "-e")
}
nc_with_e_or_c {
	contains(input.process.args[_], "-c")
}

ncat_process {
	input.process.name = "ncat"
	ncat_arg_contains_exe
}
ncat_arg_contains_exe {
     contains(input.process.args[_], "--sh-exec")
}
ncat_arg_contains_exe {
     contains(input.process.args[_], "--exec")
}
ncat_arg_contains_exe {
     contains(input.process.args[_], "-e ")
}
ncat_arg_contains_exe {
     contains(input.process.args[_], "-c ")
}
ncat_arg_contains_exe {
     contains(input.process.args[_], "--lua-exec")
}

allowed_dev_files := [
	"/dev/null", "/dev/stdin", "/dev/stdout", "/dev/stderr",
	"/dev/random", "/dev/urandom", "/dev/console", "/dev/kmsg"
]
dev_creation_binaries := [ "blkid", "rename_device", "update_engine", "sgdisk" ]


dev_creation_process {
	input.process.command = dev_creation_binaries[_]
}

open_allowed_dev_files {
	file = allowed_dev_files[_]
}

user_mgmt_binaries := ["login_binaries", "passwd_binaries", "shadowutils_binaries" ]
allowed_user_mgmt_binaries := [ "su", "sudo", "lastlog", "nologin", "unix_chkpwd" ]
run_allowed_user_mgmt_binaries {
	input.process.command = allowed_user_mgmt_binaries[_]
}

allowed_parents := [ "systemd", "systemd.postins", "udev.postinst", "run-parts", "cron", "crontab" ]
run_parent_allowed_user_mgmt_binaries {
	input.process.parent.command = allowed_user_mgmt_binaries[_]
}

User_mgmt_binaries {
    spawned_process
    input.process.command = user_mgmt_binaries[_]
    not run_allowed_user_mgmt_binaries
    not run_parent_allowed_user_mgmt_binaries
    #TODO
    #not container
    #not startswith(input.process.cmdline, "passwd -S")
    #not startswith(input.process.cmdline,"useradd -D")
    #not startswith(input.process.cmdline, "systemd --version")
    #not run_by_qualys
    #not run_by_sumologic_securefiles
    #not run_by_yum
    #not run_by_ms_oms
    #not run_by_google_accounts_daemon
}

ssh_binaries := [
    "sshd", "sftp-server", "ssh-agent",
    "ssh", "scp", "sftp",
    "ssh-keygen", "ssh-keysign", "ssh-keyscan", "ssh-add"
]
ssh_process {
	input.process.name = shell_binaries[_]
}

user_ssh_directory {
	startswith(file, "/home")
    contains(file, ".ssh")
}

open_ssh_directory {
	user_ssh_directory
}
open_ssh_directory {
	file_inside_directory("/root/.ssh")
}


inbound_outbound_syscalls := [ "accept", "listen", "connect" ]

inbound_network_connection {
	input.event.name = inbound_outbound_syscalls[_]
	input.event.params.type = "AF_INET"
	not is_ip_allowed(input.event.params.destination_ip)
}

outbound_network_connection {
	input.event.name = inbound_outbound_syscalls[_]
	input.event.params.type = "AF_INET"
	not is_ip_allowed(input.event.params.destination_ip)
}

interpreted_binaries = [ "lua", "node", "perl", "perl5", "perl6", "php", "python", "python2", "python3", "ruby", "tcl" ]
interpreted_procs {
    input.process.name = interpreted_binaries[_]
}

allowed_ips := [ "0.0.0.0", "127.0.0" ]
is_ip_allowed(ip) {
	startswith(ip, allowed_ips[_])
}

