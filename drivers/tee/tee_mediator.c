#include <linux/tee_mediator.h>
#include <linux/tee_core.h>
#include <linux/kvm_host.h>
#include <linux/mm.h>

static bool tee_host_create_acked = 0;
static bool tee_host_destroy_acked = 0;
static struct tee_mediator *mediator;

int tee_mediator_init(struct tee_mediator_ops* ops){

	if(!ops){
		return -EINVAL;
	}

	mediator = (struct tee_mediator*) kzalloc(sizeof(*mediator), GFP_KERNEL);
	if(!mediator){
		return -ENOMEM;
	}

	mediator->ops = ops;

	return 0;
}

void tee_mediator_host_create_ack(void){
	if(!mediator) return;
	if(tee_host_create_acked) return;
	if(!mediator->ops->host_create_ack) return;

	mediator->ops->host_create_ack();

	tee_host_create_acked = 1;
}

void tee_mediator_host_destroy_ack(void){
	if(!mediator) return;
	if(tee_host_destroy_acked) return;
	if(!mediator->ops->host_destroy_ack) return;

	mediator->ops->host_destroy_ack();

	tee_host_destroy_acked = 1;
}

void tee_mediator_vm_create_ack(struct kvm* kvm){
	if(!mediator) return;
	if(!kvm) return;
	if(kvm->tee_vm_created) return;
	if(!mediator->ops->vm_create_ack) return;



	mediator->ops->vm_create_ack(kvm);

	kvm->tee_vm_created = 1;
}
void tee_mediator_vm_destroy_ack(struct kvm* kvm){
	if(!mediator) return;
	if(!kvm) return;
	if(!mediator->ops->vm_destroy_ack) return;
	if(kvm->tee_vm_destroyed) return;

	mediator->ops->vm_destroy_ack(kvm);

	kvm->tee_vm_destroyed = 1;
}
