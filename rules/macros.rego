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

O_RDONLY := 1
O_WRONLY := 2


#
# sensitive files
#
sensitive_files := [
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/pam.conf",
	"/etc/security/pwquality.conf"
]

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

