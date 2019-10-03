package rules

import data.macros.sensitive_files
import data.macros.open_read
import data.macros.open_write
import data.macros.is_shell_process
import data.macros.open_shell_config_files

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
