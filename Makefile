.PHONY: help run clean total-clean force-rebuild

help:
	@echo "Available commands:"
	@echo "  make run           - Run production environment"
	@echo "  make clean         - Remove containers and volumes"
	@echo "  make total-clean   - Remove containers and built Docker images"
	@echo "  make force-rebuild - Run production environment with full rebuild "

run:
	docker-compose build
	docker-compose up

clean:
	docker-compose down -v

total-clean:
	docker-compose down --rmi all --remove-orphans --timeout 30

force-rebuild:
	docker-compose up --build --remove-orphans --force-recreate
