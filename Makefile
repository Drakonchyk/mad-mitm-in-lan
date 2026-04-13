.DEFAULT_GOAL := help

.PHONY: help prereqs networks storage render create-vms start status setup destroy rebuild

help:
	@printf '%s\n' \
		'MITM Diploma Lab' \
		'' \
		'Targets:' \
		'  make prereqs    Check host prerequisites and libvirt access' \
		'  make networks   Define and start libvirt networks' \
		'  make storage    Download base image and prepare storage pool' \
		'  make render     Generate cloud-init and rendered helper files' \
		'  make create-vms Create the lab virtual machines' \
		'  make start      Start all lab VMs' \
		'  make status     Show lab status and console hints' \
		'  make setup      Run the full setup flow' \
		'  make destroy    Tear down the lab and remove generated artifacts' \
		'  make rebuild    Destroy and recreate the full lab'

prereqs:
	./scripts/00-host-prereqs.sh

networks:
	./scripts/10-define-networks.sh

storage:
	./scripts/20-prepare-storage.sh

render:
	./scripts/30-build-cloud-init.sh

create-vms:
	./scripts/40-create-vms.sh

start:
	./scripts/50-start-lab.sh

status:
	./scripts/60-status.sh

setup:
	./scripts/setup-all.sh

destroy:
	./scripts/90-destroy-lab.sh

rebuild:
	./scripts/90-destroy-lab.sh
	./scripts/setup-all.sh
