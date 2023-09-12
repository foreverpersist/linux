# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the linux ramfs routines.
#

obj-y += ramfs.o

file-mmu-y := file-nommu.o
file-mmu-$(CONFIG_MMU) := file-mmu.o
pfs-aops-$(CONFIG_SYSCALL_ISOLATION) := pfs_address_space_operations.o
ramfs-objs += inode.o $(file-mmu-y) $(pfs-aops-y)
