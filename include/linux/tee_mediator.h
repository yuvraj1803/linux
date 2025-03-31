// SPDX-License-Identifier: GPL-2.0-only
/*
 * TEE Mediator for the Linux Kernel
 *
 * This module enables a KVM guest to interact with a
 * Trusted Execution Environment in the secure processing
 * state provided by the architecture.
 *
 * Author:
 *   Yuvraj Sakshith <yuvraj.kernel@gmail.com>
 */

#ifndef __TEE_MEDIATOR_H
#define __TEE_MEDIATOR_H

#include <linux/kvm_host.h>

struct tee_mediator_ops {
	int (*create_host)(void);
	int (*destroy_host)(void);
	int (*create_vm)(struct kvm *kvm);
	int (*destroy_vm)(struct kvm *kvm);
	void (*forward_request)(struct kvm_vcpu *vcpu);
	int (*is_active)(void);
};

struct tee_mediator {
	struct tee_mediator_ops *ops;
};

int tee_mediator_create_host(void);
int tee_mediator_destroy_host(void);
int tee_mediator_create_vm(struct kvm *kvm);
int tee_mediator_destroy_vm(struct kvm *kvm);
void tee_mediator_forward_request(struct kvm_vcpu *vcpu);
int tee_mediator_is_active(void);
int tee_mediator_register_ops(struct tee_mediator_ops *ops);

#endif
