package macros

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


sensitive_files := [
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/pam.conf",
	"/etc/security/pwquality.conf"
]

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

shell_binaries := [ "ash", "bash", "csh", "ksh", "sh", "tcsh", "zsh", "dash" ]

is_shell_process { input.process.name = shell_binaries[_] }

open_shell_config_files {
	name := shell_config_filenames[_]
	endswith(input.event.params["name"], name)
}

open_shell_config_files {
	input.event.params["name"] = shell_config_files[_]
}

open_shell_config_files {
	dir := shell_config_directories[_]
	contains(input.event.params["name"], dir)
}
