#ifndef __TEE_MEDIATOR_H
#define __TEE_MEDIATOR_H

#include <linux/kvm_host.h>
#include <linux/tee_core.h>

struct tee_mediator_ops{
	void (*vm_create_ack)(struct kvm* kvm, bool host);
	void (*vm_destroy_ack)(struct kvm* kvm, bool host);
};

struct tee_mediator{
	struct tee_mediator_ops* ops;
};

int tee_mediator_init(struct tee_mediator_ops* ops);
void tee_mediator_vm_create_ack(struct kvm* kvm, bool host);
void tee_mediator_vm_destroy_ack(struct kvm* kvm, bool host);


#endif
