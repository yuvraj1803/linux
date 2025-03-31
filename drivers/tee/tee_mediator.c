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

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/tee_mediator.h>

static struct tee_mediator *mediator;

int tee_mediator_register_ops(struct tee_mediator_ops *ops)
{

	int ret = 0;

	if (!ops) {
		ret = -EINVAL;
		goto out;
	}

	if (!mediator) {
		ret = -EOPNOTSUPP;
		goto out;
	}

	mediator->ops = ops;

out:
	return ret;
}

int tee_mediator_is_active(void)
{
	return (mediator != NULL &&
	 mediator->ops != NULL && mediator->ops->is_active());
}

int tee_mediator_create_host(void)
{
	int ret = 0;

	if (!tee_mediator_is_active() || !mediator->ops->create_host) {
		ret = -ENODEV;
		goto out;
	}

	ret = mediator->ops->create_host();

out:
	return ret;
}

int tee_mediator_destroy_host(void)
{
	int ret = 0;

	if (!tee_mediator_is_active() || !mediator->ops->destroy_host) {
		ret = -ENODEV;
		goto out;
	}

	ret = mediator->ops->destroy_host();
out:
	return ret;
}

int tee_mediator_create_vm(struct kvm *kvm)
{
	int ret = 0;

	if (!kvm) {
		ret = -EINVAL;
		goto out;
	}

	if (!tee_mediator_is_active() || !mediator->ops->create_vm) {
		ret = -ENODEV;
		goto out;
	}

	ret = mediator->ops->create_vm(kvm);

out:
	return ret;
}

int tee_mediator_destroy_vm(struct kvm *kvm)
{
	int ret = 0;

	if (!kvm) {
		ret = -EINVAL;
		goto out;
	}

	if (!tee_mediator_is_active() || !mediator->ops->destroy_vm) {
		ret = -ENODEV;
		goto out;
	}

	ret = mediator->ops->destroy_vm(kvm);

out:
	return ret;
}

void tee_mediator_forward_request(struct kvm_vcpu *vcpu)
{
	if (!vcpu || !tee_mediator_is_active() || !mediator->ops->forward_request)
		return;

	mediator->ops->forward_request(vcpu);
}

static int __init tee_mediator_init(void)
{
	int ret = 0;

	mediator = kzalloc(sizeof(*mediator), GFP_KERNEL);
	if (!mediator) {
		ret = -ENOMEM;
		goto out;
	}

	pr_info("mediator initialised\n");
out:
	return ret;
}
module_init(tee_mediator_init);

static void __exit tee_mediator_exit(void)
{
	kfree(mediator);

	pr_info("mediator exiting\n");
}
module_exit(tee_mediator_exit);
