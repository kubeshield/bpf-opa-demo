package main

/*

#include <linux/unistd.h>

#define SYSCALL_TABLE_ID0 0
#define SYSCALL_TABLE_SIZE 512

#define _packed __attribute__((packed))

enum ppm_event_type {
	PPME_GENERIC_E = 0,
	PPME_GENERIC_X = 1,
	PPME_SYSCALL_OPEN_E = 2,
	PPME_SYSCALL_OPEN_X = 3,
	PPME_SYSCALL_CLOSE_E = 4,
	PPME_SYSCALL_CLOSE_X = 5,
	PPME_SYSCALL_READ_E = 6,
	PPME_SYSCALL_READ_X = 7,
	PPME_SYSCALL_WRITE_E = 8,
	PPME_SYSCALL_WRITE_X = 9,
};

enum syscall_flags {
	UF_NONE = 0,
	UF_USED = (1 << 0),
	UF_NEVER_DROP = (1 << 1),
	UF_ALWAYS_DROP = (1 << 2),
	UF_SIMPLEDRIVER_KEEP = (1 << 3),
};

struct syscall_evt_pair {
	int flags;
	enum ppm_event_type enter_event_type;
	enum ppm_event_type exit_event_type;
} _packed;



const struct syscall_evt_pair g_syscall_table[SYSCALL_TABLE_SIZE] = {
	[__NR_open - SYSCALL_TABLE_ID0] =                       {UF_USED | UF_NEVER_DROP, PPME_SYSCALL_OPEN_E, PPME_SYSCALL_OPEN_X},
	[__NR_close - SYSCALL_TABLE_ID0] =                      {UF_USED | UF_NEVER_DROP | UF_SIMPLEDRIVER_KEEP, PPME_SYSCALL_CLOSE_E, PPME_SYSCALL_CLOSE_X},
	[__NR_read - SYSCALL_TABLE_ID0] =                       {UF_USED, PPME_SYSCALL_READ_E, PPME_SYSCALL_READ_X},
	[__NR_write - SYSCALL_TABLE_ID0] =                      {UF_USED, PPME_SYSCALL_WRITE_E, PPME_SYSCALL_WRITE_X},
};
*/
import "C"

import (
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

func populateSyscallTableMap(module *elf.Module) error {
	log := logger.WithName("[popultae-syscall-table-map]")

	syscallTableMap := module.Map("syscall_table")

	for index, syscallEvent := range C.g_syscall_table {
		key := unsafe.Pointer(&index)
		value := unsafe.Pointer(&syscallEvent)

		err := module.UpdateElement(syscallTableMap, key, value, 0)
		if err != nil {
			log.Error(err, "error updating value", "key", index, "value", syscallEvent)
			return err
		}
	}

	return nil
}
