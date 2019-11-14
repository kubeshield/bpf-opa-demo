/*
Copyright The Kubeshield Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

func populateMaps(module *elf.Module) error {
	err := populateSettingsMap(module)
	if err != nil {
		logger.Error(err, "failed to populate settings map")
		return err
	}

	err = populateSyscallTableMap(module)
	if err != nil {
		logger.Error(err, "error populating syscall table map")
		return err
	}

	err = populateFillerTableMap(module)
	if err != nil {
		logger.Error(err, "error populating syscall table map")
		return err
	}

	err = populateEventTableMap(module)
	if err != nil {
		logger.Error(err, "error populating event table map")
		return err
	}

	return nil
}

func populateSettingsMap(m *elf.Module) error {
	log := logger.WithName("[popultae-settings-map]")

	type bpfSettings struct {
		capture_enabled bool
	}

	settingsMap := m.Map("settings_map")
	key := 0
	settings := bpfSettings{}
	err := m.LookupElement(settingsMap, unsafe.Pointer(&key), unsafe.Pointer(&settings))
	if err != nil {
		log.Error(err, "failed to lookup settings map", "key", key, "settings", settings)
		return err
	}

	settings.capture_enabled = true
	err = m.UpdateElement(settingsMap, unsafe.Pointer(&key), unsafe.Pointer(&settings), 0)
	if err != nil {
		log.Error(err, "failed to update settings map", "key", key, "settings", settings)
		return err
	}

	return nil
}
