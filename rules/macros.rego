package macros

sensitive_files := [
	"/etc/shadow",
	"/etc/sudoers",
	"/etc/pam.conf",
	"/etc/security/pwquality.conf"
]

open_events := [2, 3, 306, 307]

is_open {
	input.event.type = open_events[_]
}
