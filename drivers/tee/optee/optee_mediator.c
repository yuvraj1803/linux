// SPDX-License-Identifier: GPL-2.0-only
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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "optee_mediator.h"
#include "optee_smc.h"
#include "optee_msg.h"
#include "optee_private.h"
#include "optee_rpc_cmd.h"

#include <linux/tee_mediator.h>
#include <linux/kvm_host.h>
#include <linux/arm-smccc.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm_types.h>
#include <linux/minmax.h>

#include <asm/kvm_emulate.h>

#define OPTEE_KNOWN_NSEC_CAPS	OPTEE_SMC_NSEC_CAP_UNIPROCESSOR
#define OPTEE_KNOWN_SEC_CAPS	(OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM | \
								OPTEE_SMC_SEC_CAP_UNREGISTERED_SHM | \
								OPTEE_SMC_SEC_CAP_DYNAMIC_SHM | \
								OPTEE_SMC_SEC_CAP_MEMREF_NULL)

static struct optee_mediator *mediator;
static spinlock_t mediator_lock;
static u32 optee_thread_limit;

static void copy_regs_from_vcpu(struct kvm_vcpu *vcpu, struct guest_regs *regs)
{
	if (!vcpu || !regs)
		return;

	regs->a0 = vcpu_get_reg(vcpu, 0);
	regs->a1 = vcpu_get_reg(vcpu, 1);
	regs->a2 = vcpu_get_reg(vcpu, 2);
	regs->a3 = vcpu_get_reg(vcpu, 3);
	regs->a4 = vcpu_get_reg(vcpu, 4);
	regs->a5 = vcpu_get_reg(vcpu, 5);
	regs->a6 = vcpu_get_reg(vcpu, 6);
	regs->a7 = vcpu_get_reg(vcpu, 7);
}

static void copy_smccc_res_to_vcpu(struct kvm_vcpu *vcpu, struct arm_smccc_res *res)
{

	vcpu_set_reg(vcpu, 0, res->a0);
	vcpu_set_reg(vcpu, 1, res->a1);
	vcpu_set_reg(vcpu, 2, res->a2);
	vcpu_set_reg(vcpu, 3, res->a3);
}

static void optee_mediator_smccc_smc(struct guest_regs *regs, struct arm_smccc_res *res)
{

	arm_smccc_smc(regs->a0, regs->a1, regs->a2, regs->a3,
	 regs->a4, regs->a5, regs->a6, regs->a7, res);
}

static int optee_mediator_pin_guest_page(struct kvm *kvm, gpa_t gpa)
{

	int ret = 0;

	gfn_t gfn = gpa >> PAGE_SHIFT;

	struct kvm_memory_slot *memslot = gfn_to_memslot(kvm, gfn);

	if (!memslot) {
		ret = -EAGAIN;
		goto out;
	}

	struct page *pages;

	if (!pin_user_pages_unlocked(memslot->userspace_addr,
								1,
								&pages,
								FOLL_LONGTERM)) {
		ret = -EAGAIN;
		goto out;
	}

out:
	return ret;
}

static void optee_mediator_unpin_guest_page(struct kvm *kvm, gpa_t gpa)
{

	gfn_t gfn = gpa >> PAGE_SHIFT;

	struct page *page = gfn_to_page(kvm, gfn);

	if (!page)
		goto out;

	unpin_user_page(page);

out:
	return;
}

static struct optee_vm_context *optee_mediator_find_vm_context(struct kvm *kvm)
{

	struct optee_vm_context *vm_context, *tmp;
	int found = 0;

	if (!kvm)
		goto out;

	mutex_lock(&mediator->vm_list_lock);

	list_for_each_entry_safe(vm_context, tmp, &mediator->vm_list, list) {
		if (vm_context->kvm == kvm) {
			found = 1;
			break;
		}
	}

	mutex_unlock(&mediator->vm_list_lock);

out:
	if (!found)
		return NULL;

	return vm_context;
}

static void optee_mediator_add_vm_context(struct optee_vm_context *vm_context)
{

	if (!vm_context)
		goto out;

	mutex_lock(&mediator->vm_list_lock);
	list_add_tail(&vm_context->list, &mediator->vm_list);
	mutex_unlock(&mediator->vm_list_lock);

out:
	return;
}

static void optee_mediator_delete_vm_context(struct optee_vm_context *vm_context)
{

	struct optee_vm_context *cursor_vm_context, *tmp;
	struct optee_std_call *call, *tmp_call;
	struct optee_shm_rpc *shm_rpc, *tmp_shm_rpc;
	struct optee_shm_buf *shm_buf, *tmp_shm_buf;

	if (!vm_context)
		goto out;

	mutex_lock(&vm_context->lock);

	list_for_each_entry_safe(call, tmp_call, &vm_context->std_call_list, list) {
		if (call) {
			optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) call->guest_arg_gpa);

			list_del(&call->list);
			kfree(call->shadow_arg);
			kfree(call);
		}
	}


	list_for_each_entry_safe(shm_buf, tmp_shm_buf, &vm_context->shm_buf_list, list) {
		if (shm_buf) {

			for (int j = 0; j < shm_buf->num_pages; j++)
				optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) shm_buf->guest_page_list[j]);

			list_del(&shm_buf->list);
			kfree(shm_buf->shadow_buffer_list);
			kfree(shm_buf->guest_page_list);
			kfree(shm_buf);
		}
	}

	list_for_each_entry_safe(shm_rpc, tmp_shm_rpc, &vm_context->shm_rpc_list, list) {
		if (shm_rpc) {
			optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) shm_rpc->rpc_arg_gpa);
			list_del(&shm_rpc->list);
			kfree(shm_rpc);
		}
	}


	mutex_unlock(&vm_context->lock);

	mutex_lock(&mediator->vm_list_lock);

	list_for_each_entry_safe(cursor_vm_context, tmp, &mediator->vm_list, list) {
		if (cursor_vm_context == vm_context) {
			list_del(&cursor_vm_context->list);
			kfree(cursor_vm_context);

			goto out_unlock;
		}
	}

out_unlock:
	mutex_unlock(&mediator->vm_list_lock);
out:
	return;
}

static struct optee_std_call *optee_mediator_new_std_call(void)
{
	struct optee_std_call *call = kzalloc(sizeof(*call),  GFP_KERNEL);

	if (!call)
		return NULL;

	return call;
}

static void optee_mediator_del_std_call(struct optee_std_call *call)
{
	if (!call)
		return;

	kfree(call);
}

static void optee_mediator_enlist_std_call(struct optee_vm_context *vm_context, struct optee_std_call *call)
{
	mutex_lock(&vm_context->lock);
	list_add_tail(&call->list, &vm_context->std_call_list);
	vm_context->call_count++;
	mutex_unlock(&vm_context->lock);

	optee_mediator_pin_guest_page(vm_context->kvm, (gpa_t) call->guest_arg_gpa);
}

static void optee_mediator_delist_std_call(struct optee_vm_context *vm_context, struct optee_std_call *call)
{
	mutex_lock(&vm_context->lock);
	list_del(&call->list);
	vm_context->call_count--;
	mutex_unlock(&vm_context->lock);

	optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) call->guest_arg_gpa);
}

static struct optee_std_call *optee_mediator_find_std_call(struct optee_vm_context *vm_context, u32 thread_id)
{
	struct optee_std_call *call;
	int found = 0;

	mutex_lock(&vm_context->lock);
	list_for_each_entry(call, &vm_context->std_call_list, list) {
		if (call->thread_id == thread_id) {
			found = 1;
			break;
		}
	}
	mutex_unlock(&vm_context->lock);

	if (!found)
		return NULL;

	return call;
}

static struct optee_shm_buf *optee_mediator_new_shm_buf(void)
{
	struct optee_shm_buf *shm_buf = kzalloc(sizeof(*shm_buf),  GFP_KERNEL);

	return shm_buf;
}

static void optee_mediator_enlist_shm_buf(struct optee_vm_context *vm_context, struct optee_shm_buf *shm_buf)
{
	mutex_lock(&vm_context->lock);
	list_add_tail(&shm_buf->list, &vm_context->shm_buf_list);
	vm_context->shm_buf_page_count += shm_buf->num_pages;
	mutex_unlock(&vm_context->lock);

	for (int i = 0; i < shm_buf->num_pages; i++)
		optee_mediator_pin_guest_page(vm_context->kvm, (gpa_t) shm_buf->guest_page_list[i]);
}

static void optee_mediator_free_shm_buf(struct optee_vm_context *vm_context, u64 cookie)
{

	struct optee_shm_buf *shm_buf, *tmp;

	mutex_lock(&vm_context->lock);
	list_for_each_entry_safe(shm_buf, tmp, &vm_context->shm_buf_list, list) {
		if (shm_buf->cookie == cookie) {
			for (int buf = 0; buf < shm_buf->num_buffers; buf++)
				kfree(shm_buf->shadow_buffer_list[buf]);

			for (int buf = 0; buf < shm_buf->num_pages; buf++)
				optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) shm_buf->guest_page_list[buf]);

			vm_context->shm_buf_page_count -= shm_buf->num_pages;

			list_del(&shm_buf->list);

			kfree(shm_buf->shadow_buffer_list);
			kfree(shm_buf->guest_page_list);
			kfree(shm_buf);
			break;
		}
	}
	mutex_unlock(&vm_context->lock);
}

static void optee_mediator_free_all_buffers(struct optee_vm_context *vm_context, struct optee_std_call *call)
{

	for (int i = 0; i < call->shadow_arg->num_params; i++) {
		u64 attr = call->shadow_arg->params[i].attr;

		switch (attr & OPTEE_MSG_ATTR_TYPE_MASK) {

		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			optee_mediator_free_shm_buf(vm_context, call->shadow_arg->params[i].u.tmem.shm_ref);
			break;
		default:
			break;

		}
	}
}

static void optee_mediator_free_shm_buf_page_list(struct optee_vm_context *vm_context, u64 cookie)
{
	mutex_lock(&vm_context->lock);

	struct optee_shm_buf *shm_buf;

	list_for_each_entry(shm_buf, &vm_context->shm_buf_list, list) {
		if (shm_buf->cookie == cookie) {
			for (int entry = 0; entry < shm_buf->num_buffers; entry++) {
				kfree(shm_buf->shadow_buffer_list[entry]);
				shm_buf->shadow_buffer_list[entry] = NULL;
			}
			break;
		}
	}

	mutex_unlock(&vm_context->lock);
}

static struct optee_shm_rpc *optee_mediator_new_shm_rpc(void)
{
	struct optee_shm_rpc *shm_rpc = kzalloc(sizeof(*shm_rpc),  GFP_KERNEL);

	return shm_rpc;
}

static void optee_mediator_enlist_shm_rpc(struct optee_vm_context *vm_context, struct optee_shm_rpc *shm_rpc)
{
	mutex_lock(&vm_context->lock);
	list_add_tail(&shm_rpc->list, &vm_context->shm_rpc_list);
	mutex_unlock(&vm_context->lock);

	optee_mediator_pin_guest_page(vm_context->kvm, (gpa_t) shm_rpc->rpc_arg_gpa);
}

static struct optee_shm_rpc *optee_mediator_find_shm_rpc(struct optee_vm_context *vm_context, u64 cookie)
{

	struct optee_shm_rpc *shm_rpc;
	int found = 0;

	mutex_lock(&vm_context->lock);
	list_for_each_entry(shm_rpc, &vm_context->shm_rpc_list, list) {
		if (shm_rpc->cookie == cookie) {
			found = 1;
			break;
		}
	}
	mutex_unlock(&vm_context->lock);

	if (!found)
		return NULL;

	return shm_rpc;
}

static void optee_mediator_free_shm_rpc(struct optee_vm_context *vm_context, u64 cookie)
{

	struct optee_shm_rpc *shm_rpc, *tmp;

	mutex_lock(&vm_context->lock);

	list_for_each_entry_safe(shm_rpc, tmp, &vm_context->shm_rpc_list, list) {
		if (shm_rpc->cookie == cookie) {

			optee_mediator_unpin_guest_page(vm_context->kvm, (gpa_t) shm_rpc->rpc_arg_gpa);

			list_del(&shm_rpc->list);
			kfree(shm_rpc);
			break;
		}
	}

	mutex_unlock(&vm_context->lock);
}

static hva_t optee_mediator_gpa_to_hva(struct kvm *kvm, gpa_t gpa)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;

	struct page *page = gfn_to_page(kvm, gfn);

	if (!page)
		return 0;

	hva_t hva = (hva_t) page_to_virt(page);
	return hva;
}

static hva_t optee_mediator_gpa_to_phys(struct kvm *kvm, gpa_t gpa)
{
	gfn_t gfn = gpa >> PAGE_SHIFT;

	struct page *page = gfn_to_page(kvm, gfn);

	if (!page)
		return 0;

	phys_addr_t phys = (phys_addr_t) page_to_phys(page);
	return phys;
}


static int optee_mediator_shadow_msg_arg(struct kvm *kvm, struct optee_std_call *call)
{

	int ret = 0;

	call->shadow_arg = kzalloc(OPTEE_MSG_NONCONTIG_PAGE_SIZE,  GFP_KERNEL);

	if (!call->shadow_arg) {
		ret = OPTEE_SMC_RETURN_ENOMEM;
		goto out;
	}

	ret = kvm_read_guest(kvm, (gpa_t)call->guest_arg_gpa, (void *) call->shadow_arg, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

out:

	return ret;
}

static void optee_mediator_shadow_arg_sync(struct optee_std_call *call)
{



	call->guest_arg_hva->ret = call->shadow_arg->ret;
	call->guest_arg_hva->ret_origin = call->shadow_arg->ret_origin;
	call->guest_arg_hva->session = call->shadow_arg->session;

	for (int i = 0; i < call->shadow_arg->num_params; i++) {
		u32 attr = call->shadow_arg->params[i].attr;

		switch (attr & OPTEE_MSG_ATTR_TYPE_MASK) {

		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			call->guest_arg_hva->params[i].u.tmem.size =
				call->shadow_arg->params[i].u.tmem.size;
			continue;
		case OPTEE_MSG_ATTR_TYPE_RMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INOUT:
			call->guest_arg_hva->params[i].u.rmem.size =
				call->shadow_arg->params[i].u.rmem.size;
			continue;
		case OPTEE_MSG_ATTR_TYPE_VALUE_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_VALUE_INOUT:
			call->guest_arg_hva->params[i].u.value.a =
				call->shadow_arg->params[i].u.value.a;
			call->guest_arg_hva->params[i].u.value.b =
				call->shadow_arg->params[i].u.value.b;
			call->guest_arg_hva->params[i].u.value.c =
				call->shadow_arg->params[i].u.value.c;
			continue;
		case OPTEE_MSG_ATTR_TYPE_NONE:
		case OPTEE_MSG_ATTR_TYPE_RMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
			continue;

		}
	}
}

static int optee_mediator_resolve_noncontig(struct optee_vm_context *vm_context, struct optee_msg_param *param)
{

	int ret = 0;

	if (!param->u.tmem.buf_ptr)
		goto out;

	struct kvm *kvm = vm_context->kvm;

	struct page_data *guest_buffer_gpa = (struct page_data *) param->u.tmem.buf_ptr;
	struct page_data *guest_buffer_hva = (struct page_data *) optee_mediator_gpa_to_hva(kvm, (gpa_t) guest_buffer_gpa);

	if (!guest_buffer_hva) {
		ret = -EINVAL;
		goto out;
	}

	u64 guest_buffer_size = param->u.tmem.size;
	u64 guest_buffer_offset = param->u.tmem.buf_ptr & (OPTEE_MSG_NONCONTIG_PAGE_SIZE - 1);
	u64 num_entries = DIV_ROUND_UP(guest_buffer_size + guest_buffer_offset, OPTEE_MSG_NONCONTIG_PAGE_SIZE);

	mutex_lock(&vm_context->lock);
	if (vm_context->shm_buf_page_count + num_entries > OPTEE_MAX_SHM_BUFFER_PAGES) {
		ret = -ENOMEM;
		mutex_unlock(&vm_context->lock);
		goto out;
	}
	mutex_unlock(&vm_context->lock);

	u64 num_buffers = DIV_ROUND_UP(num_entries, OPTEE_BUFFER_ENTRIES);

	struct page_data **shadow_buffer_list = kzalloc(num_buffers * sizeof(struct page_data *), GFP_KERNEL);

	if (!shadow_buffer_list) {
		ret = -ENOMEM;
		goto out;
	}

	gpa_t *guest_page_list = kzalloc(num_entries * sizeof(gpa_t), GFP_KERNEL);

	if (!guest_page_list) {
		ret = -ENOMEM;
		goto out_free_shadow_buffer_list;
	}

	u32 guest_page_num = 0;

	for (int i = 0; i < num_buffers; i++) {
		struct page_data *shadow_buffer = kzalloc(sizeof(struct page_data),  GFP_KERNEL);

		if (!shadow_buffer) {
			ret = -ENOMEM;
			goto out_free_guest_page_list;
		}

		for (int entry = 0; entry < MIN(num_entries, OPTEE_BUFFER_ENTRIES); entry++) {
			gpa_t buffer_entry_gpa = guest_buffer_hva->pages_list[entry];

			guest_page_list[guest_page_num++] = buffer_entry_gpa;

			phys_addr_t buffer_entry_phys = optee_mediator_gpa_to_phys(kvm, buffer_entry_gpa);

			shadow_buffer->pages_list[entry] = (u64) buffer_entry_phys;
		}

		shadow_buffer_list[i] = shadow_buffer;
		if (i > 0)
			shadow_buffer_list[i-1]->next_page_data = (u64) virt_to_phys(shadow_buffer_list[i]);

		guest_buffer_hva = (struct page_data *) optee_mediator_gpa_to_hva(kvm, (gpa_t) guest_buffer_hva->next_page_data);
		if (!guest_buffer_hva && (i != num_buffers - 1)) {
			ret = -EINVAL;
			goto out_free_guest_page_list;
		}

	}

	struct optee_shm_buf *shm_buf = optee_mediator_new_shm_buf();

	if (!shm_buf) {
		ret = -ENOMEM;
		goto out_free_guest_page_list;
	}

	shm_buf->shadow_buffer_list = shadow_buffer_list;
	shm_buf->num_buffers = num_buffers;
	shm_buf->guest_page_list = guest_page_list;
	shm_buf->num_pages = num_entries;
	shm_buf->cookie = param->u.tmem.shm_ref;

	optee_mediator_enlist_shm_buf(vm_context, shm_buf);

	param->u.tmem.buf_ptr = (u64) virt_to_phys(shadow_buffer_list[0]) | guest_buffer_offset;

	return ret;

out_free_guest_page_list:
	kfree(guest_page_list);
out_free_shadow_buffer_list:
	for (int i = 0; i < num_buffers; i++)
		kfree(shadow_buffer_list[i]);

	kfree(shadow_buffer_list);
out:
	return ret;
}

static int optee_mediator_resolve_params(struct optee_vm_context *vm_context, struct optee_std_call *call)
{

	int ret = 0;

	for (int i = 0; i < call->shadow_arg->num_params; i++) {
		u32 attr = call->shadow_arg->params[i].attr;

		switch (attr & OPTEE_MSG_ATTR_TYPE_MASK) {

		case OPTEE_MSG_ATTR_TYPE_TMEM_INPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_OUTPUT:
		case OPTEE_MSG_ATTR_TYPE_TMEM_INOUT:
			if (attr & OPTEE_MSG_ATTR_NONCONTIG) {
				ret = optee_mediator_resolve_noncontig(vm_context, call->shadow_arg->params + i);

				if (ret == -ENOMEM) {
					call->shadow_arg->ret_origin = TEEC_ORIGIN_COMMS;
					call->shadow_arg->ret = TEEC_ERROR_OUT_OF_MEMORY;
					goto out;
				}
				if (ret == -EINVAL) {
					call->shadow_arg->ret_origin = TEEC_ORIGIN_COMMS;
					call->shadow_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
					goto out;
				}
			} else {
				if (call->shadow_arg->params[i].u.tmem.buf_ptr) {
					call->shadow_arg->ret_origin = TEEC_ORIGIN_COMMS;
					call->shadow_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
					ret = -EINVAL;
					goto out;
				}
			}
		default:
			continue;

		}
	}
out:

	return ret;
}


static int optee_mediator_new_vmid(u64 *vmid_out)
{

	int ret = 0;

	u64 vmid = atomic_read(&mediator->next_vmid);

	atomic_inc(&mediator->next_vmid);

	*vmid_out = vmid;

	return ret;
}

static int optee_mediator_create_host(void)
{

	int ret = 0;

	struct arm_smccc_res res;

	arm_smccc_smc(OPTEE_SMC_VM_CREATED, OPTEE_HOST_VMID, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_SMC_RETURN_ENOTAVAIL) {
		ret = -EBUSY;
		goto out;
	}

out:
	return ret;
}

static int optee_mediator_destroy_host(void)
{

	int ret = 0;

	struct arm_smccc_res res;

	arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, OPTEE_HOST_VMID, 0, 0, 0, 0, 0, 0, &res);

	return ret;
}

static int optee_mediator_create_vm(struct kvm *kvm)
{

	int ret = 0;
	struct arm_smccc_res res;

	if (!kvm) {
		ret = -EINVAL;
		goto out;
	}

	struct optee_vm_context *vm_context = kzalloc(sizeof(*vm_context), GFP_KERNEL);

	if (!vm_context) {
		ret = -ENOMEM;
		goto out;
	}

	ret = optee_mediator_new_vmid(&vm_context->vmid);
	if (ret < 0)
		goto out_context_free;

	INIT_LIST_HEAD(&vm_context->std_call_list);
	INIT_LIST_HEAD(&vm_context->shm_buf_list);
	INIT_LIST_HEAD(&vm_context->shm_rpc_list);

	mutex_init(&vm_context->lock);

	vm_context->kvm = kvm;

	arm_smccc_smc(OPTEE_SMC_VM_CREATED, vm_context->vmid, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_SMC_RETURN_ENOTAVAIL) {
		ret = -EBUSY;
		goto out_context_free;
	}

	optee_mediator_add_vm_context(vm_context);

out:
	return ret;
out_context_free:
	kfree(vm_context);
	return ret;
}

static int optee_mediator_destroy_vm(struct kvm *kvm)
{

	int ret = 0;
	struct arm_smccc_res res;

	if (!kvm) {
		ret = -EINVAL;
		goto out;
	}

	struct optee_vm_context *vm_context = optee_mediator_find_vm_context(kvm);

	if (!vm_context) {
		ret = -EINVAL;
		goto out;
	}

	arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, vm_context->vmid, 0, 0, 0, 0, 0, 0, &res);

	optee_mediator_delete_vm_context(vm_context);

out:
	return ret;
}

static void optee_mediator_handle_fast_call(struct kvm_vcpu *vcpu, struct guest_regs *regs)
{

	struct arm_smccc_res res;
	struct kvm *kvm = vcpu->kvm;

	struct optee_vm_context *vm_context = optee_mediator_find_vm_context(kvm);

	if (!vm_context) {
		res.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out;
	}

	regs->a7 = vm_context->vmid;

	optee_mediator_smccc_smc(regs, &res);

	switch (ARM_SMCCC_FUNC_NUM(regs->a0)) {

	case OPTEE_SMC_FUNCID_GET_THREAD_COUNT:
		optee_thread_limit = 0;
		if (res.a0 != OPTEE_SMC_RETURN_UNKNOWN_FUNCTION)
			optee_thread_limit = res.a1;
		break;

	case OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE:
		if (res.a0 == OPTEE_SMC_RETURN_OK) {
			u64 cookie = (u64) reg_pair_to_ptr(res.a1, res.a2);

			optee_mediator_free_shm_buf(vm_context, cookie);
		}
		break;

	default:
		break;

	}

	copy_smccc_res_to_vcpu(vcpu, &res);
out:
	return;
}

static int optee_mediator_handle_rpc_return(struct optee_vm_context *vm_context,
											struct optee_std_call *call,
											struct guest_regs *regs,
											struct arm_smccc_res *res)
{

	int ret = 0;

	call->rpc_state.a0 = res->a0;
	call->rpc_state.a1 = res->a1;
	call->rpc_state.a2 = res->a2;
	call->rpc_state.a3 = res->a3;

	call->rpc_func = OPTEE_SMC_RETURN_GET_RPC_FUNC(res->a0);
	call->thread_id = res->a3;

	if (call->rpc_func == OPTEE_SMC_RPC_FUNC_FREE) {
		u64 cookie = (u64) reg_pair_to_ptr(res->a1, res->a2);

		optee_mediator_free_shm_rpc(vm_context, cookie);
	}

	if (call->rpc_func == OPTEE_SMC_RPC_FUNC_CMD) {
		u64 cookie = (u64) reg_pair_to_ptr(res->a1, res->a2);
		struct optee_shm_rpc *shm_rpc = optee_mediator_find_shm_rpc(vm_context, cookie);

		if (!shm_rpc) {
			ret = -ERESTART;
			goto out;
		}
		if (shm_rpc->rpc_arg_hva->cmd == OPTEE_RPC_CMD_SHM_FREE)
			optee_mediator_free_shm_buf(vm_context, shm_rpc->rpc_arg_hva->params[0].u.value.b);
	}

out:
	return ret;
}

static void optee_mediator_do_call_with_arg(struct optee_vm_context *vm_context,
										    struct optee_std_call *call,
										    struct guest_regs *regs,
										    struct arm_smccc_res *res)
{

	regs->a7 = vm_context->vmid;

	optee_mediator_smccc_smc(regs, res);

	if (OPTEE_SMC_RETURN_IS_RPC(res->a0)) {
		while (optee_mediator_handle_rpc_return(vm_context, call, regs, res) == -ERESTART) {
			optee_mediator_smccc_smc(regs, res);
			if (!OPTEE_SMC_RETURN_IS_RPC(res->a0))
				break;
		}
	} else {

		u32 cmd = call->shadow_arg->cmd;
		u32 call_ret = call->shadow_arg->ret;

		switch (cmd) {

		case OPTEE_MSG_CMD_REGISTER_SHM:
			if (call_ret == 0)
				optee_mediator_free_shm_buf_page_list(vm_context, (u64) call->shadow_arg->params[0].u.tmem.shm_ref);
			else
				optee_mediator_free_shm_buf(vm_context, (u64) call->shadow_arg->params[0].u.tmem.shm_ref);

			break;

		case OPTEE_MSG_CMD_UNREGISTER_SHM:
			if (call_ret == 0)
				optee_mediator_free_shm_buf(vm_context, (u64) call->shadow_arg->params[0].u.rmem.shm_ref);
			break;

		default:
			optee_mediator_free_all_buffers(vm_context, call);
			break;

		}
	}
}

static void optee_mediator_handle_std_call(struct kvm_vcpu *vcpu, struct guest_regs *regs)
{

	struct arm_smccc_res res;
	struct kvm *kvm = vcpu->kvm;
	int ret;

	struct optee_vm_context *vm_context = optee_mediator_find_vm_context(kvm);

	if (!vm_context) {
		res.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out_copy;
	}

	struct optee_std_call *call = optee_mediator_new_std_call();

	if (!call) {
		res.a0 = OPTEE_SMC_RETURN_ENOMEM;
		goto out_copy;
	}

	call->thread_id = 0xffffffff;
	call->guest_arg_gpa = (struct optee_msg_arg *) reg_pair_to_ptr(regs->a1, regs->a2);
	call->guest_arg_hva = (struct optee_msg_arg *) optee_mediator_gpa_to_hva(kvm, (gpa_t) call->guest_arg_gpa);

	if (!call->guest_arg_hva) {
		res.a0 = OPTEE_SMC_RETURN_EBADADDR;
		goto out_call_free;
	}

	mutex_lock(&vm_context->lock);

	if (vm_context->call_count >= optee_thread_limit) {
		res.a0 = OPTEE_SMC_RETURN_ETHREAD_LIMIT;
		mutex_unlock(&vm_context->lock);
		goto out_call_free;
	}

	mutex_unlock(&vm_context->lock);

	INIT_LIST_HEAD(&call->list);

	ret = optee_mediator_shadow_msg_arg(kvm, call);
	if (ret) {
		res.a0 = OPTEE_SMC_RETURN_EBADADDR;
		goto out_call_free;
	}

	optee_mediator_enlist_std_call(vm_context, call);

	if (OPTEE_MSG_GET_ARG_SIZE(call->shadow_arg->num_params) > OPTEE_MSG_NONCONTIG_PAGE_SIZE) {
		call->shadow_arg->ret = TEEC_ERROR_BAD_PARAMETERS;
		call->shadow_arg->ret_origin = TEEC_ORIGIN_COMMS;
		call->shadow_arg->num_params = 0;

		optee_mediator_shadow_arg_sync(call);
		goto out_delist_std_call;
	}


	u32 cmd = call->shadow_arg->cmd;


	switch (cmd) {

	case OPTEE_MSG_CMD_OPEN_SESSION:
	case OPTEE_MSG_CMD_CLOSE_SESSION:
	case OPTEE_MSG_CMD_INVOKE_COMMAND:
	case OPTEE_MSG_CMD_CANCEL:
	case OPTEE_MSG_CMD_REGISTER_SHM:
	case OPTEE_MSG_CMD_UNREGISTER_SHM:
		ret = optee_mediator_resolve_params(vm_context, call);
		if (ret) {
			res.a0 = OPTEE_SMC_RETURN_OK;
			optee_mediator_shadow_arg_sync(call);
			goto out_delist_std_call;
		}
		break;
	default:
	    res.a0 = OPTEE_SMC_RETURN_EBADCMD;
		goto out_delist_std_call;
	}

	reg_pair_from_64(&regs->a1, &regs->a2, (u64) virt_to_phys(call->shadow_arg));
	regs->a3 = OPTEE_SMC_SHM_CACHED;

	optee_mediator_do_call_with_arg(vm_context, call, regs, &res);
	optee_mediator_shadow_arg_sync(call);

	if (OPTEE_SMC_RETURN_IS_RPC(res.a0))
		goto out_copy;

out_delist_std_call:
	optee_mediator_delist_std_call(vm_context, call);
out_call_free:
	optee_mediator_del_std_call(call);
out_copy:
	copy_smccc_res_to_vcpu(vcpu, &res);
}

static void optee_mediator_handle_rpc_alloc(struct optee_vm_context *vm_context, struct guest_regs *regs)
{

	u64 ptr = (u64) reg_pair_to_ptr(regs->a1, regs->a2);
	u64 cookie = (u64) reg_pair_to_ptr(regs->a4, regs->a5);

	struct optee_shm_rpc *shm_rpc = optee_mediator_new_shm_rpc();

	if (!shm_rpc)
		goto out_err;

	struct optee_shm_rpc *temp_shm_rpc = optee_mediator_find_shm_rpc(vm_context, cookie);

	if (temp_shm_rpc) { // guest is trying to reuse cookie
		goto out_err;
	}

	shm_rpc->rpc_arg_gpa = (struct optee_msg_arg *) ptr;
	shm_rpc->rpc_arg_hva = (struct optee_msg_arg *) optee_mediator_gpa_to_hva(vm_context->kvm, (gpa_t) shm_rpc->rpc_arg_gpa);

	if (!shm_rpc->rpc_arg_hva) {
		ptr = 0;
		goto out_err_free_rpc;
	}

	shm_rpc->cookie = cookie;

	optee_mediator_enlist_shm_rpc(vm_context, shm_rpc);

	ptr = optee_mediator_gpa_to_phys(vm_context->kvm, (gpa_t) shm_rpc->rpc_arg_gpa);

	reg_pair_from_64(&regs->a1, &regs->a2, ptr);
	return;

out_err_free_rpc:
	kfree(shm_rpc);
out_err:
	reg_pair_from_64(&regs->a1, &regs->a2, 0);
}

static int optee_mediator_handle_rpc_cmd(struct optee_vm_context *vm_context, struct guest_regs *regs)
{
	int ret = 0;
	u64 cookie = (u64) reg_pair_to_ptr(regs->a1, regs->a2);

	struct optee_shm_rpc *shm_rpc = optee_mediator_find_shm_rpc(vm_context, cookie);

	if (!shm_rpc) {
		ret = -EINVAL;
		goto out;
	}

	if (OPTEE_MSG_GET_ARG_SIZE(shm_rpc->rpc_arg_hva->num_params) > OPTEE_MSG_NONCONTIG_PAGE_SIZE) {
		shm_rpc->rpc_arg_hva->ret = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	switch (shm_rpc->rpc_arg_hva->cmd) {
	case OPTEE_RPC_CMD_SHM_ALLOC:
		ret = optee_mediator_resolve_noncontig(vm_context, shm_rpc->rpc_arg_hva->params + 0);
		break;

	case OPTEE_RPC_CMD_SHM_FREE:
		optee_mediator_free_shm_buf(vm_context, shm_rpc->rpc_arg_hva->params[0].u.value.b);
		break;
	}

out:
	return ret;
}

static void optee_mediator_handle_rpc_call(struct kvm_vcpu *vcpu, struct guest_regs *regs)
{

	int ret = 0;
	struct arm_smccc_res res;
	struct optee_std_call *call;
	u32 thread_id = regs->a3;

	struct optee_vm_context *vm_context = optee_mediator_find_vm_context(vcpu->kvm);

	if (!vm_context) {
		res.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out_copy;
	}

	call = optee_mediator_find_std_call(vm_context, thread_id);
	if (!call) {
		res.a0 = OPTEE_SMC_RETURN_ERESUME;
		goto out_copy;
	}


	call->thread_id = 0xffffffff;

	switch (call->rpc_func) {

	case OPTEE_SMC_RPC_FUNC_ALLOC:
		optee_mediator_handle_rpc_alloc(vm_context, regs);
		break;
	case OPTEE_SMC_RPC_FUNC_FOREIGN_INTR:
		break;
	case OPTEE_SMC_RPC_FUNC_CMD:
		ret = optee_mediator_handle_rpc_cmd(vm_context, regs);

		if (ret < 0)
			goto out;
		break;
	}



	optee_mediator_do_call_with_arg(vm_context, call, regs, &res);

	optee_mediator_shadow_arg_sync(call);

	if (OPTEE_SMC_RETURN_IS_RPC(res.a0) || res.a0 == OPTEE_SMC_RETURN_ERESUME)
		goto out_copy;

	optee_mediator_delist_std_call(vm_context, call);
	optee_mediator_del_std_call(call);
out_copy:
	copy_smccc_res_to_vcpu(vcpu, &res);
out:
	return;
}

static void optee_mediator_handle_exchange_cap(struct kvm_vcpu *vcpu, struct guest_regs *regs)
{

	struct arm_smccc_res res;
	struct kvm *kvm = vcpu->kvm;

	struct optee_vm_context *vm_context = optee_mediator_find_vm_context(kvm);

	if (!vm_context) {
		res.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out_copy;
	}

	regs->a1 &= OPTEE_KNOWN_NSEC_CAPS;
	regs->a7 = vm_context->vmid;

	optee_mediator_smccc_smc(regs, &res);
	if (res.a0 != OPTEE_SMC_RETURN_OK)
		goto out_copy;

	res.a1 &= OPTEE_KNOWN_SEC_CAPS;
	res.a1 &= ~OPTEE_SMC_SEC_CAP_HAVE_RESERVED_SHM;

	if (!(res.a1 & OPTEE_SMC_SEC_CAP_DYNAMIC_SHM)) {
		res.a0 = OPTEE_SMC_RETURN_ENOTAVAIL;
		goto out_copy;
	}

out_copy:
	copy_smccc_res_to_vcpu(vcpu, &res);
}

static void optee_mediator_forward_smc(struct kvm_vcpu *vcpu)
{

	if (!vcpu)
		goto out;

	struct guest_regs regs;

	copy_regs_from_vcpu(vcpu, &regs);

	switch (ARM_SMCCC_FUNC_NUM(regs.a0)) {

	case OPTEE_SMC_FUNCID_CALLS_COUNT:
	case OPTEE_SMC_FUNCID_CALLS_UID:
	case OPTEE_SMC_FUNCID_CALLS_REVISION:
	case OPTEE_SMC_FUNCID_GET_OS_UUID:
	case OPTEE_SMC_FUNCID_GET_OS_REVISION:
	case OPTEE_SMC_FUNCID_GET_THREAD_COUNT:
	case OPTEE_SMC_FUNCID_ENABLE_ASYNC_NOTIF:
	case OPTEE_SMC_FUNCID_ENABLE_SHM_CACHE:
	case OPTEE_SMC_FUNCID_GET_ASYNC_NOTIF_VALUE:
	case OPTEE_SMC_FUNCID_DISABLE_SHM_CACHE:
		optee_mediator_handle_fast_call(vcpu, &regs);
		break;

	case OPTEE_SMC_FUNCID_EXCHANGE_CAPABILITIES:
		optee_mediator_handle_exchange_cap(vcpu, &regs);
		break;

	case OPTEE_SMC_FUNCID_CALL_WITH_ARG:
		optee_mediator_handle_std_call(vcpu, &regs);
		break;

	case OPTEE_SMC_FUNCID_RETURN_FROM_RPC:
		optee_mediator_handle_rpc_call(vcpu, &regs);
		break;

	default:
		vcpu_set_reg(vcpu, 0, OPTEE_SMC_RETURN_UNKNOWN_FUNCTION);
		break;
	}

out:
	return;
}

static int optee_mediator_is_active(void)
{

	int ret = 1;

	spin_lock(&mediator_lock);

	if (!mediator)
		ret = 0;

	spin_unlock(&mediator_lock);

	return ret;
}

struct tee_mediator_ops optee_mediator_ops = {
	.create_host = optee_mediator_create_host,
	.destroy_host = optee_mediator_destroy_host,
	.create_vm = optee_mediator_create_vm,
	.destroy_vm = optee_mediator_destroy_vm,
	.forward_request = optee_mediator_forward_smc,
	.is_active = optee_mediator_is_active,
};

static int optee_check_virtualization(void)
{

	int ret = 0;

	struct arm_smccc_res res;

	arm_smccc_smc(OPTEE_SMC_VM_DESTROYED, 0, 0, 0, 0, 0, 0, 0, &res);

	if (res.a0 == OPTEE_SMC_RETURN_UNKNOWN_FUNCTION) {
		ret = -ENODEV;
		goto out;
	}

out:
	return ret;
}

static int optee_check_page_size(void)
{
	if (OPTEE_MSG_NONCONTIG_PAGE_SIZE > PAGE_SIZE)
		return -EINVAL;

	return 0;
}

static int __init optee_mediator_init(void)
{

	int ret;

	ret = optee_check_virtualization();
	if (ret < 0) {
		pr_info("optee virtualization unsupported\n");
		goto out;
	}

	ret = optee_check_page_size();
	if (ret < 0) {
		pr_info("optee noncontig page size too large");
		goto out;
	}

	mediator = kzalloc(sizeof(*mediator), GFP_KERNEL);
	if (!mediator) {
		ret = -ENOMEM;
		goto out;
	}

	ret = tee_mediator_register_ops(&optee_mediator_ops);
	if (ret < 0)
		goto out_free;

	atomic_set(&mediator->next_vmid, 2); // VMID 0 is reserved for the hypervisor and 1 is for host.

	INIT_LIST_HEAD(&mediator->vm_list);
	mutex_init(&mediator->vm_list_lock);
	spin_lock_init(&mediator_lock);

	pr_info("mediator initialised\n");

out:
	return ret;
out_free:
	kfree(mediator);
	return ret;
}
module_init(optee_mediator_init);

static void __exit optee_mediator_exit(void)
{

	struct optee_vm_context *vm_context;
	struct optee_vm_context *tmp;

	list_for_each_entry_safe(vm_context, tmp, &mediator->vm_list, list) {
		list_del(&vm_context->list);
		kfree(vm_context);
	}

	kfree(mediator);

	pr_info("mediator exiting\n");

}
module_exit(optee_mediator_exit);
