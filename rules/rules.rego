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
import data.macros.chmod
import data.macros.is_setuid_or_setgid
import data.macros.delete_shell_history
import data.macros.rename_shell_history
import data.macros.data_remove_process
import data.macros.access_log_files
import data.macros.o_trunc_flag_set
import data.macros.search_private_key
import data.macros.search_password
import data.macros.network_tool_procs
import data.macros.nc_process
import data.macros.ncat_process
import data.macros.open_create
import data.macros.dev_creation_process
import data.macros.open_allowed_dev_files
import data.macros.file
import data.macros.inbound_network_connection
import data.macros.ssh_process
import data.macros.open_ssh_directory
import data.macros.modify
import data.macros.mkdir
import data.macros.bin_dirs
import data.macros.modify_file
import data.macros.inbound_network_connection
import data.macros.outbound_network_connection
import data.macros.interpreted_procs
import data.macros.http_proxy_procs
import data.macros.outbound_network_connection
import data.macros.inbound_network_connection
import data.macros.allowed_outbound_destination_domains
import data.macros.allowed_inbound_destination_domains
import data.macros.rpm_procs
import data.macros.ansible_running_python
import data.macros.python_running_chef
import data.macros.exe_running_docker_save
import data.macros.amazon_linux_running_python_yum
import data.macros.net_miner_pool
import data.macros.package_management_ancestor_process
import data.macros.inside_container
import data.macros.k8s_api_server
import data.macros.proc_in_change_thread_ns_binaries
import data.macros.user_management_binaries
import data.macros.process_in_allowed_bins
import data.macros.process_in_allowed_parent_user_mgmt_bins
import data.macros.inbound_outbound
import data.macros.expected_udp_traffic
import data.macros.monitored_dir
import data.macros.google_accounts_daemon_writing_ssh
import data.macros.cloud_init_writing_ssh
import data.macros.coreos_write_ssh_dir
import data.macros.python_running_ms_oms
import data.macros.protected_shell_spawner
import data.macros.proc_cmdline_in_known_cmdlines
import data.macros.in_system_users
import data.macros.interactive
import data.macros.process_in_known_setuid_bins
import data.macros.sensitive_mount

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

enable_create_hidden_file_or_directory { false }

create_hidden_file_or_directory = input {
	enable_create_hidden_file_or_directory
	rename_to_hidden_file
}
create_hidden_file_or_directory = input {
	enable_create_hidden_file_or_directory
	mkdir_hidden_directory
}
create_hidden_file_or_directory = input {
	enable_create_hidden_file_or_directory
	create_hidden_file
}

set_setuid_or_setgid_bit = input {
	chmod
	is_setuid_or_setgid
}

delete_or_rename_shell_history = input {
	delete_shell_history
}
delete_or_rename_shell_history = input {
	rename_shell_history
}

remove_bulk_data_from_disk = input {
	spawned_process
	input.process.command = data_remove_process[_]
}

clear_log_activities = input {
	open_write
	access_log_files
	o_trunc_flag_set
	#TODO
	#not trusted_logging_image
}

search_private_key_or_password = input {
	not input.process.name == "systemd"
	search_private_key
}
search_private_key_or_password = input {
	not input.process.name == "systemd"
	search_password
}

Launch_Suspicious_Network_Tool = input {
    spawned_process
    network_tool_procs
}

Netcat_Remote_Code_Execution = input {
	nc_process
}
Netcat_Remote_Code_Execution = input {
	ncat_process
}

# (we may need to add additional checks against false positives, see:
# https://bugs.launchpad.net/ubuntu/+source/rkhunter/+bug/86153)
Create_files_below_dev = input {
	startswith(file, "/dev")
	open_create
	not dev_creation_process
	not startswith(file, "/dev/tty")
	not open_allowed_dev_files
}

disallowed_ssh_connection = input {
	inbound_network_connection
	input.event.params.source_port = 22
}

read_ssh_information = input {
	open_read
	not ssh_process
	open_ssh_directory
}

modify_binary_dirs = input {
	modify
	modify_file(bin_dirs[_])
	not package_management_process
}

mkdir_binary_dirs = input {
	mkdir
	contains(input.event.params.pathname, bin_dirs[_])
	not package_management_process
}

launch_suspicious_network_tool_on_host = input {
	spawned_process
	network_tool_procs
}

interpreted_procs_inbound_network_activity = input {
	inbound_network_connection
	interpreted_procs
}

interpreted_procs_outbound_network_activity = input {
	outbound_network_connection
	interpreted_procs
}

program_run_with_disallowed_http_proxy_env = input {
	spawned_process
	http_proxy_procs
	contains("HTTP_PROXY", input.process.args[_])
}

unexpected_outbound_connection_destination = input {
	outbound_network_connection
	contains(input.event.params.DNS[_],  allowed_outbound_destination_domains[_])
}

unexpected_inbound_connection_source = input {
	inbound_network_connection
	contains(input.event.params.DNS[_],  allowed_inbound_destination_domains[_])
}

write_below_rpm_database = input {
	open_write
	startswith(file, "/var/lib/rpm")
	not rpm_procs
	not ansible_running_python
	not python_running_chef
	not exe_running_docker_save
	not amazon_linux_running_python_yum
}

Detect_outbound_connections_to_common_miner_pool_ports = input {
	net_miner_pool
}

Detect_crypto_miners_using_the_Stratum_protocol = input {
	spawned_process
	input.process.args[_] = "stratum+tcp"
}

Launch_Package_Management_Process_in_Container = input {
	spawned_process
	inside_container
	package_management_process
	not package_management_ancestor_process
}

Contact_K8S_API_Server_From_Container = input {
	outbound_network_connection
	k8s_api_server
	inside_container
}

Unexpected_K8s_NodePort_Connection = input {
	outbound_network_connection
	inside_container
	input.event.params.destination_port >= 30000
	input.event.params.destination_port <= 32767
}

Change_thread_namespace = input {
	input.event.type = "setns"
	not proc_in_change_thread_ns_binaries
	not startswith(input.process.name, "runc")
	not startswith(input.process.name, "containerd")
}

Contact_EC2_Instance_Metadata_Service_From_Container = input {
	outbound_network_connection
	input.event.params.destination_ip = "169.254.169.254"
	inside_container
}

User_mgmt_binaries = input {
	spawned_process
	input.process.name = user_management_binaries[_]
	not inside_container
	not process_in_allowed_bins
	not process_in_allowed_parent_user_mgmt_bins

	cmdline := concat(" ", input.process.args)
    not startswith(cmdline, "passwd -S")
    not startswith(cmdline, "useradd -D")
    not startswith(cmdline, "systemd --version")
}

Unexpected_UDP_Traffic = input {
	inbound_outbound
	not expected_udp_traffic
	input.event.params.socket.type = "udp"
}


Write_below_monitored_dir = input {
	open_write
	monitored_dir
	not package_management_process
    not exe_running_docker_save
    not python_running_get_pip
    not python_running_ms_oms
    not google_accounts_daemon_writing_ssh
    not cloud_init_writing_ssh
    not coreos_write_ssh_dir
}

Run_shell_untrusted = input {
    spawned_process
    is_shell_process
    protected_shell_spawner
    not proc_cmdline_in_known_cmdlines
}

System_user_interactive = input {
	spawned_process
	in_system_users
	interactive
}

Non_sudo_setuid = input {
    input.event.name = "setuid"
    not inside_container
    not input.process.username = "root"
    not process_in_known_setuid_bins
    not startswith(input.process.name, "runc:")
}

Launch_Privileged_Container = input {
	input.process.pod.spec.containers[_].securityContext.privileged
}
Launch_Privileged_Container = input {
	input.process.pod.spec.initContainers[_].securityContext.privileged
}

Launch_Sensitive_Mount_Container = input {
	sensitive_mount
}
