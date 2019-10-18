package rules

import data.macros.sensitive_files
import data.macros.open_read
import data.macros.open_write
import data.macros.is_shell_process
import data.macros.open_shell_config_files
import data.macros.update_cron_config
import data.macros.start_crontab
import data.macros.write_repository
import data.macros.package_management_process
import data.macros.bin_dir
import data.macros.python_running_get_pip
import data.macros.create_symlink
import data.macros.symlink_target_in_sensitive_file
import data.macros.spawned_process
import data.macros.remote_copy_procs
import data.macros.rename_to_hidden_file
import data.macros.mkdir_hidden_directory
import data.macros.create_hidden_file

open_sensitive_files = input {
	open_read
	input.event.params["name"] = sensitive_files[_]
}

modify_shell_configuration_file = input {
	open_write
	not is_shell_process
	open_shell_config_files
}

read_shell_configuration_file = input {
	open_read
	not is_shell_process
	open_shell_config_files
}

schedule_cron_jobs = input {
	update_cron_config
}

schedule_cron_jobs = input {
	start_crontab
}

update_package_repository = input {
	write_repository
	not package_management_process
}

write_binary_dir = input {
	bin_dir
	open_write
	not package_management_process
    not python_running_get_pip
}

create_sysmlink_over_sensitive_files = input {
	create_symlink
	symlink_target_in_sensitive_file
}

launch_remote_file_copy_tool_in_container {
	spawned_process
	# TODO:
	# container //checks if inside container
	remote_copy_procs

}

create_hidden_file_or_directory = input {
	rename_to_hidden_file
}
create_hidden_file_or_directory = input {
	mkdir_hidden_directory
}
create_hidden_file_or_directory = input {
	create_hidden_file
}
