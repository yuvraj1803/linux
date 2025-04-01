/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * OP-TEE Mediator for the Linux Kernel
 *
 * This module enables a KVM guest to interact with OP-TEE
 * in the secure world by hooking event handlers with
 * the TEE Mediator layer.
 *
 * Author:
 *   Yuvraj Sakshith <yuvraj.kernel@gmail.com>
 */

#ifndef __OPTEE_MEDIATOR_H
#define __OPTEE_MEDIATOR_H

#include "optee_msg.h"

#include <linux/types.h>
#include <linux/mm_types.h>
#include <linux/kvm_types.h>
#include <linux/list.h>
#include <linux/mutex.h>

#define OPTEE_HYP_CLIENT_ID		0
#define OPTEE_HOST_VMID			1
#define OPTEE_BUFFER_ENTRIES ((OPTEE_MSG_NONCONTIG_PAGE_SIZE / sizeof(u64)) - 1)
#define OPTEE_MAX_SHM_BUFFER_PAGES 512

struct optee_mediator {
	struct list_head vm_list;
	struct mutex vm_list_lock;

	atomic_t next_vmid;
};

struct optee_vm_context {
	struct list_head list;
	struct list_head std_call_list;
	struct list_head shm_buf_list;
	struct list_head shm_rpc_list;

	struct mutex lock;

	struct kvm *kvm;
	u64 vmid;
	u32 call_count;
	u64 shm_buf_page_count;
};

struct guest_regs {
	u32 a0;
	u32 a1;
	u32 a2;
	u32 a3;
	u32 a4;
	u32 a5;
	u32 a6;
	u32 a7;
};

struct optee_std_call {
	struct list_head list;

	struct optee_msg_arg *guest_arg_gpa;
	struct optee_msg_arg *guest_arg_hva;
	struct optee_msg_arg *shadow_arg;

	u32 thread_id;

	u32 rpc_func;
	u64 rpc_buffer_type;

	struct guest_regs rpc_state;
};

struct page_data {
	u64 pages_list[OPTEE_BUFFER_ENTRIES];
	u64 next_page_data;
};

struct optee_shm_buf {
	struct list_head list;

	struct page_data **shadow_buffer_list;
	u64 num_buffers;

	gpa_t *guest_page_list;
	u64 num_pages;

	u64 cookie;
};

struct optee_shm_rpc {
	struct list_head list;

	struct optee_msg_arg *rpc_arg_gpa;
	struct optee_msg_arg *rpc_arg_hva;

	u64 cookie;
};


#endif
