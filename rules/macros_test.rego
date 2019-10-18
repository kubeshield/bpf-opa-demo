package macros

#
# test open_write
#
test_open_write_neg_fd {
	not open_write with input as { "event" : { "name": "open", "params" : { "fd" : -1, "flags" : 1 } } }
}
test_open_write_pos_fd_wrong_flag {
	not open_write with input as { "event" : { "name": "open", "params" : { "fd" : 1, "flags" : 1 } } }
}
test_open_write_pos_fd_corr_flag {
	open_write with input as { "event" : { "name": "open", "params" : { "fd" : 1, "flags" : 2 } } }
}

#
# test open_read
#
test_open_read_neg_fd {
	not open_read with input as { "event" : { "name": "open", "params" : { "fd" : -1, "flags" : 1 } } }
}
test_open_read_pos_fd_wrong_flag {
	not open_read with input as { "event" : { "name": "open", "params" : { "fd" : 1, "flags" : 0 } } }
}
test_open_read_pos_fd_corr_flag {
	open_read with input as { "event" : { "name": "open", "params" : { "fd" : 1, "flags" : 1 } } }
}

#
# test open_event
#
test_open_event_open {
	open_event with input as { "event" : { "name" : "open" } }
}
test_open_event_openat {
	open_event with input as { "event" : { "name" : "openat" } }
}
test_open_event_false {
	not open_event with input as { "event" : { "name" : "write" } }
}

#
# test is_open_read
#
test_is_open_read_flag_0 {
	not is_open_read with input as { "event" : { "params" : { "flags" : 0 } } }
}
test_is_open_read_flag_1 {
	is_open_read with input as { "event" : { "params" : { "flags" : 1 } } }
}
test_is_open_read_flag_2 {
	not is_open_read with input as { "event" : { "params" : { "flags" : 2 } } }
}
test_is_open_read_flag_3 {
	is_open_read with input as { "event" : { "params" : { "flags" : 3 } } }
}
test_is_open_read_flag_4 {
	not is_open_read with input as { "event" : { "params" : { "flags" : 4 } } }
}
test_is_open_read_flag_5 {
	is_open_read with input as { "event" : { "params" : { "flags" : 5 } } }
}

#
# test is_open_write
#
test_is_open_write_flag_0 {
	not is_open_write with input as { "event" : { "params" : { "flags" : 0 } } }
}
test_is_open_write_flag_1 {
	not is_open_write with input as { "event" : { "params" : { "flags" : 1 } } }
}
test_is_open_write_flag_2 {
	is_open_write with input as { "event" : { "params" : { "flags" : 2 } } }
}
test_is_open_write_flag_3 {
	is_open_write with input as { "event" : { "params" : { "flags" : 3 } } }
}
test_is_open_write_flag_4 {
	not is_open_write with input as { "event" : { "params" : { "flags" : 4 } } }
}

#
# test is_shell_process
#
test_is_shell_process_false {
	not is_shell_process with input as { "process" : { "name" : "vim" } }
}
test_is_shell_process_bash {
	is_shell_process with input as { "process" : { "name" : "bash" } }
}
test_is_shell_process_zsh {
	is_shell_process with input as { "process" : { "name" : "zsh" } }
}

#
# test open_shell_config_files
#
test_open_shell_config_files_bashrc {
	open_shell_config_files with input as { "event" : { "params" : { "name" : ".bashrc" } } }
}
test_open_shell_config_files_bash_history {
	open_shell_config_files with input as { "event" : { "params" : { "name" : ".bash_history" } } }
}
test_open_shell_config_files_zshrc {
	open_shell_config_files with input as { "event" : { "params" : { "name" : ".zshrc" } } }
}
test_open_shell_config_files_etc_profile {
	open_shell_config_files with input as { "event" : { "params" : { "name" : "/etc/profile" } } }
}
test_open_shell_config_files_etc_cshlogin {
	open_shell_config_files with input as { "event" : { "params" : { "name" : "/etc/csh.login" } } }
}
test_open_shell_config_files_etc_zsh {
	open_shell_config_files with input as { "event" : { "params" : { "name" : "/etc/zsh" } } }
}

#
# test is_shell_process
#
test_is_shell_process {
	is_shell_process with input as { "process" : { "name" : "bash" } }
}
test_is_shell_process {
	not is_shell_process with input as { "process" : { "name" : "test" } }
}

#
# test update_cron_config
#
test_update_cron_config {
	update_cron_config with input as { "event" : { "name": "open", "params" : { "name" : "/etc/cron/config", "fd" : 1, "flags" : 2 } } }
}
test_update_cron_config_not_open_write {
	not update_cron_config with input as { "event" : { "name": "open", "params" : { "name" : "/etc/cron/config", "fd" : 1, "flags" : 0 } } }
}
test_update_cron_config_not_not_cron_dir {
	not update_cron_config with input as { "event" : { "name": "open", "params" : { "name" : "/test/cron", "fd" : 1, "flags" : 2 } } }
}

#
# test start_crontab
#
test_start_crontab {
	start_crontab with input as { "event" : { "name": "execve" }, "process" : { "executable" : "crontab" } }
}
test_start_crontab_not_execve {
	not start_crontab with input as { "event" : { "name": "openat" }, "process" : { "executable" : "crontab" } }
}
test_start_crontab_not_crontab {
	not start_crontab with input as { "event" : { "name": "execve" }, "process" : { "executable" : "notcrontab" } }
}


#
# test files and dirs
#
test_file {
    filename := file with input as { "event": { "params": { "name": "/usr/bin/crontab" } } }
    filename = "/usr/bin/crontab"
}

test_directory {
    file_inside_directory("/usr/bin") with input as { "event": { "params": { "name": "/usr/bin/crontab" } } }
}
test_directory {
    not file_inside_directory("/usr/bin") with input as { "event": { "params": { "name": "/usr/crontab" } } }
}

#
# test modify
#
test_modify {
	modify with input as { "event" : { "name" : "rename" } }
}
test_modify {
	modify with input as { "event" : { "name" : "rmdir" } }
}

#
# test mkdir
#
test_mkdir {
	mkdir with input as { "event" : { "name" : "mkdir" } }
}
test_mkdir {
	mkdir with input as { "event" : { "name" : "mkdirat" } }
}

#
# test rpm_procs
#
test_rpm_procs {
	rpm_procs with input as { "process" : { "name" : "salt-minion" } }
}
test_rpm_procs {
	rpm_procs with input as { "process" : { "name" : "dnf" } }
}
test_rpm_procs {
	rpm_procs with input as { "process" : { "name" : "probe_rpminfo" } }
}

#
# test package management process
#
test_package_management_process {
	package_management_process with input as { "process" : { "executable" : "dpkg" } }
}
test_package_management_process {
	package_management_process with input as { "process" : { "executable" : "pip" } }
}
test_package_management_process {
	not package_management_process with input as { "process" : { "executable" : "vim" } }
}

#
# test access_repositories
#
test_access_repositories {
	access_repositories with input as { "event": { "params" : { "name" : "sources.list" } } }
}
test_access_repositories {
	not access_repositories with input as { "event": { "params" : { "name" : "test" } } }
}
test_access_repositories {
	access_repositories with input as { "event": { "params" : { "name" : "/etc/apt/sources.list.d/test" } } }
}

#
# test modify_repositories
#
test_modify_repositories {
	modify_repositories with input as { "event": { "params" : { "pathname" : "/etc/apt/sources.list.d/test" } } }
}
test_modify_repositories {
	not modify_repositories with input as { "event": { "params" : { "pathname" : "test" } } }
}

#
# test write_repository
#
test_write_repository {
	write_repository with input as { "event" : { "name": "open", "params" : { "name" : "sources.list", "fd" : 1, "flags" : 2 } } }
}
test_write_repository_not_open_write {
	not write_repository with input as { "event" : { "name": "open", "params" : { "name": "sources.list", "fd" : 1, "flags" : 0 } } }
}
test_write_repository_not_sources_list {
	not write_repository with input as { "event" : { "name": "open", "params" : { "name": "test", "fd" : 1, "flags" : 2 } } }
}
test_write_repository {
	write_repository with input as { "event": { "name" : "rename", "params" : { "pathname" : "/etc/apt/sources.list.d/test" } } }
}
test_write_repository_not_modify {
	not write_repository with input as { "event": { "name" : "mkdir", "params" : { "pathname" : "/etc/apt/sources.list.d/test" } } }
}
test_write_repository_not_write_repo {
	not write_repository with input as { "event": { "name" : "rename", "params" : { "pathname" : "test" } } }
}

#
# test bin_dir
#
test_bin_dir_true {
	bin_dir with input as { "event" : { "params" : { "name" : "/bin" } } }
}
test_bin_dir_false {
	not bin_dir with input as { "event" : { "params" : { "name" : "/test" } } }
}

#
# test python pip
#
test_python_running_get_pip {
	python_running_get_pip with input as { "process" : { "command" : "python", "args": [ "get-pop.py" ] } }
}
test_python_running_get_pip {
	not python_running_get_pip with input as { "process" : { "command" : "python", "args": [ "help" ] } }
}

#
# test python ms oms
#
test_python_running_ms_oms {
	python_running_ms_oms with input as { "process" : { "command" : "python", "args": [ "/var/lib/waagnet/" ] } }
}
test_python_running_ms_oms_false {
	not python_running_ms_oms with input as { "process" : { "command" : "python", "args": [ "test" ] } }
}

#
# test docker process
#
# TODO:
#test_exe_running_docker_save {
#	exe_running_docker_save with input as { "process" : { "command" : "docker", "args": [ "/var/lib/waagnet/" ] } }
#	startswith(input.process.cmdline, "exe /var/lib/docker")
#	input.process.parent.command = docker_process[_]
#}
