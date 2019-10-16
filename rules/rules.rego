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

#- rule: Write below binary dir
#  desc: an attempt to write to any file below a set of binary directories
#  condition: >
#    and not exe_running_docker_save
#    and not python_running_ms_oms
#  output: >
#    File below a known binary directory opened for writing (user=%user.name
#    command=%proc.cmdline file=%fd.name parent=%proc.pname pcmdline=%proc.pcmdline gparent=%proc.aname[2] container_id=%container.id image=%container.image.repository)
#  priority: ERROR
#  tags: [filesystem, mitre_persistence]
