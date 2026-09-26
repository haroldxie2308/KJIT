// SPDX-License-Identifier: GPL-2.0
/*
 * Minimal PID 1 for the KJIT QEMU bring-up initramfs.
 *
 * Loads /kjit.ko (what `insmod` does: finit_module), unloads it, then powers
 * the guest off so a foreground `make qemu-run` terminates. The module's own
 * PASS/FAIL lines reach the serial console through printk.
 */
#include <fcntl.h>
#include <stdio.h>
#include <sys/reboot.h>
#include <sys/syscall.h>
#include <unistd.h>

static void power_off(void)
{
	sync();
	reboot(RB_POWER_OFF);
	perror("kjit-init: reboot(RB_POWER_OFF)");
	for (;;)
		pause();
}

int main(void)
{
	int fd = open("/kjit.ko", O_RDONLY | O_CLOEXEC);

	if (fd < 0) {
		perror("kjit-init: open /kjit.ko");
		power_off();
	}
	if (syscall(SYS_finit_module, fd, "", 0) != 0) {
		perror("kjit-init: insmod kjit.ko");
		power_off();
	}
	printf("kjit-init: insmod kjit.ko ok\n");
	fflush(stdout);

	if (syscall(SYS_delete_module, "kjit", O_NONBLOCK) != 0)
		perror("kjit-init: rmmod kjit");
	else
		printf("kjit-init: rmmod kjit ok\n");
	fflush(stdout);

	power_off();
	return 0;
}
