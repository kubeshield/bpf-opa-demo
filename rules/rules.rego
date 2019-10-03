package rules

import data.macros.sensitive_files
import data.macros.open_read
import data.macros.open_write
import data.macros.is_shell_process
import data.macros.open_shell_config_files
import data.macros.update_cron_config
import data.macros.start_crontab

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


#- rule: Schedule Cron Jobs
#  desc: Detect cron jobs scheduled
#  condition: >
#    ((open_write and fd.name startswith /etc/cron) or
#     (spawned_process and proc.name = "crontab"))
#  output: >
#    Cron jobs were scheduled to run (user=%user.name command=%proc.cmdline
#    file=%fd.name container_id=%container.id container_name=%container.name image=%container.image.repository:%container.image.tag)
#  priority:
#    NOTICE
#  tag: [file, mitre_persistence]
