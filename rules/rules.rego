package rules

import data.macros.sensitive_files
import data.macros.is_open

open_sensitive_files = input {
	is_open
	input.event.params["name"] = sensitive_files[_]
	input.event.params["fd"] > 0
}
