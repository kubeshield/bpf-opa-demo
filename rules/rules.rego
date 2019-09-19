package rules

import data.macros.sensitive_files
import data.macros.is_open

open_sensitive_files = input {
	is_open
	input.params["name"] = sensitive_files[_]
	input.params["fd"] > 0
}
