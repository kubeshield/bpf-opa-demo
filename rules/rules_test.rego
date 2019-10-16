package rules

#
# test open_sensitive_files
#
test_open_sensitive_file {
	open_sensitive_files with input as { "event" : { "name": "open", "params" : { "name" : "/etc/shadow", "fd" : 1, "flags" : 1 } } }
}
test_open_sensitive_file_ {
	open_sensitive_files with input as { "event" : { "name": "openat", "params" : { "name" : "/etc/shadow", "fd" : 1, "flags" : 1 } } }
}
test_open_sensitive_file_false {
	not open_sensitive_files with input as { "event" : { "name": "open", "params" : { "name" : "/hello/world", "fd" : 1, "flags" : 1 } } }
}

#
# test modify_shell_configuration_file
#
test_modify_shell_configuration_file {
	modify_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 2 }}, "process": {"name": "vim" }}
}
test_modify_shell_configuration_file_not_write {
	not modify_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 0 }}, "process": {"name": "vim" }}
}
test_modify_shell_configuration_file_shell_proc {
	not modify_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 0 }}, "process": {"name": "bash" }}
}
test_modify_shell_configuration_file_not_shell_config {
	not modify_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": "test", "fd": 1, "flags": 2 }}, "process": {"name": "vim" }}
}

#
# test read_shell_config_file
#
test_read_shell_config_file {
	read_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 1 }}, "process": {"name": "vim" }}
}
test_read_shell_config_file_not_read {
	not read_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 2 }}, "process": {"name": "vim" }}
}
test_read_shell_config_file_shell_proc {
	not read_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": ".bashrc", "fd": 1, "flags": 1 }}, "process": {"name": "bash" }}
}
test_read_shell_config_file_not_shell_config {
	not read_shell_configuration_file with input as {"event": {"name": "open", "params": {"name": "test", "fd": 1, "flags": 1 }}, "process": {"name": "vim" }}
}

#
# test schedule_cron_jobs
#
test_schedule_cron_jobs {
	schedule_cron_jobs with input as { "event" : { "name": "open", "params" : { "name" : "/etc/cron/config", "fd" : 1, "flags" : 2 } } }
}
test_schedule_cron_jobs {
	schedule_cron_jobs with input as { "event" : { "name": "execve" }, "process" : { "executable" : "crontab" } }
}

#
# test update_package_repository
#
test_update_package_repository {
	update_package_repository with input as { "event" : { "name": "open", "params" : { "name" : "sources.list", "fd" : 1, "flags" : 2 } }, "process" : { "executable": "vim" } }
}
test_update_package_repository_valid_process {
	not update_package_repository with input as { "event" : { "name": "open", "params" : { "name" : "sources.list", "fd" : 1, "flags" : 2 } }, "process" : { "executable": "dpkg" } }
}
test_update_package_repository_not_write_repo {
	not update_package_repository with input as { "event" : { "name": "open", "params" : { "name" : "test", "fd" : 1, "flags" : 2 } }, "process" :{ "executable":  "vim" }}
}

#
# test write bin dir
#
test_write_bin_dir {
	write_binary_dir with input as { "event" : { "name": "open", "params" : { "name": "/bin", "fd" : 1, "flags" : 2 } }, "process" : { "executable" : "cp" } }
}
test_write_bin_dir_not_wrte {
	not write_binary_dir with input as { "event" : { "name": "not_write", "params" : { "name": "/bin", "fd" : 1, "flags" : 2 } }, "process" : { "executable" : "cp" } }
}
test_write_bin_dir_pkg_bin {
	not write_binary_dir with input as { "event" : { "name": "open", "params" : { "name": "/bin", "fd" : 1, "flags" : 2 } }, "process" : { "executable" : "dpkg" } }
}
