#ifndef __TEE_MEDIATOR_H
#define __TEE_MEDIATOR_H

#include <linux/kvm_host.h>
#include <linux/tee_core.h>

struct tee_mediator_ops{
	void (*host_create_ack)(void);
	void (*host_destroy_ack)(void);
	void (*vm_create_ack)(struct kvm* kvm);
	void (*vm_destroy_ack)(struct kvm* kvm);

};

struct tee_mediator{
	struct tee_mediator_ops* ops;
};

int tee_mediator_init(struct tee_mediator_ops* ops);
void tee_mediator_host_create_ack(void);
void tee_mediator_host_destroy_ack(void);
void tee_mediator_vm_create_ack(struct kvm* kvm);
void tee_mediator_vm_destroy_ack(struct kvm* kvm);


#endif
