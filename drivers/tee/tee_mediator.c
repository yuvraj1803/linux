#include <linux/tee_mediator.h>
#include <linux/tee_core.h>
#include <linux/kvm_host.h>

void tee_vm_create_ack(struct tee_context *ctx, struct kvm* kvm){
	if(!ctx || !kvm) return;
	if(!ctx->teedev->desc->ops->vm_create_ack) return;

	ctx->teedev->desc->ops->vm_create_ack(ctx, kvm);

}
void tee_vm_destroy_ack(struct tee_context *ctx, struct kvm* kvm){
	if(!ctx || !kvm) return;
	if(!ctx->teedev->desc->ops->vm_destroy_ack) return;

	ctx->teedev->desc->ops->vm_destroy_ack(ctx, kvm);
}
