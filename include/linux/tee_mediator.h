#ifndef __TEE_MEDIATOR_H
#define __TEE_MEDIATOR_H

#include <linux/kvm_host.h>
#include <linux/tee_core.h>

void tee_vm_create_ack(struct tee_context *ctx, struct kvm* kvm);
void tee_vm_destroy_ack(struct tee_context *ctx, struct kvm* kvm);

#endif
