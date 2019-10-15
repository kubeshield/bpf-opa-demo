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
