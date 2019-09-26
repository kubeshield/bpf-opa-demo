package rules

import data.macros.sensitive_files
import data.macros.open_read

open_sensitive_files = input {
	open_read
	input.event.params["name"] = sensitive_files[_]
}
