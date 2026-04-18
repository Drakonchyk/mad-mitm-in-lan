.PHONY: prereqs networks storage render create-vms start status setup destroy rebuild

prereqs:
	./shell/lab/host-prereqs.sh

networks:
	./shell/lab/define-networks.sh

storage:
	./shell/lab/prepare-storage.sh

render:
	./shell/lab/build-cloud-init.sh

create-vms:
	./shell/lab/create-vms.sh

start:
	./shell/lab/start-lab.sh

status:
	./shell/lab/status.sh

setup:
	./shell/lab/setup-lab.sh

destroy:
	./shell/lab/destroy-lab.sh

rebuild:
	./shell/lab/destroy-lab.sh
	./shell/lab/setup-lab.sh
