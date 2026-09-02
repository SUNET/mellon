# ==============================================================================
# Configuration Variables
# ==============================================================================

NAME                    := mellon
VERSION                 ?= latest
CURRENT_BRANCH          := $(shell git rev-parse --abbrev-ref HEAD)

# Docker Configuration
REGISTRY                := docker.sunet.se/iam_vc
DOCKER_TAG              := $(REGISTRY)/$(NAME):$(VERSION)

# ==============================================================================
# Phony Targets Declaration
# ==============================================================================

.PHONY: docker-build docker-push start stop restart release check_current_branch gosec staticcheck vulncheck fmt vscode

# ==============================================================================
# Docker Build
# ==============================================================================

docker-build: ## Build Docker image
	$(info Docker Building $(NAME) with tag: $(VERSION))
	docker build --tag $(DOCKER_TAG) .

# ==============================================================================
# Docker Push
# ==============================================================================

docker-push: ## Push Docker image (refuses :latest unless FORCE=true)
	@if [ "$(VERSION)" = "latest" ] && [ "$(FORCE)" != "true" ]; then \
		echo "Error: refusing to push $(DOCKER_TAG). Set VERSION=vX.Y.Z or pass FORCE=true to override."; exit 1; \
	fi
	$(info Pushing $(DOCKER_TAG))
	docker push $(DOCKER_TAG)

# ==============================================================================
# Development Environment
# ==============================================================================

vscode: ## Set up VS Code development environment
	$(info Installing go packages)
	go install github.com/securego/gosec/v2/cmd/gosec@latest && \
	go install golang.org/x/vuln/cmd/govulncheck@latest && \
	go install honnef.co/go/tools/cmd/staticcheck@latest && \
	go install mvdan.cc/gofumpt@latest

# ==============================================================================
# Release Management
# ==============================================================================

BUMP                    ?= patch
FORCE                   ?=

check_current_branch:
	$(info Current branch: $(CURRENT_BRANCH))
ifeq ($(CURRENT_BRANCH),main)
	$(info On main branch)
else
ifneq ($(FORCE),true)
	$(error Not on main branch — use FORCE=true to override)
else
	$(warning Not on main branch — continuing because FORCE=true)
endif
endif

release: check_current_branch ## Create and push a git tag (BUMP=major|minor|patch)
	@echo "$(BUMP)" | grep -qE '^(major|minor|patch)$$' || \
		{ echo "Error: BUMP must be major, minor, or patch (got: $(BUMP))"; exit 1; }
	@if [ "$(FORCE)" != "true" ] && ! git diff --quiet HEAD 2>/dev/null; then \
		echo "Error: working tree is dirty — commit or stash changes first (use FORCE=true to override)"; exit 1; \
	fi
	@LATEST=$$(git tag -l "v*" --sort=-v:refname | grep -E '^v[0-9]+\.[0-9]+\.[0-9]+$$' | head -n1); \
	if [ -z "$$LATEST" ]; then \
		echo "No existing version tags found, starting at v0.0.0"; \
		LATEST="v0.0.0"; \
	fi; \
	CURRENT=$$(echo "$$LATEST" | sed 's/^v//'); \
	MAJOR=$$(echo "$$CURRENT" | cut -d. -f1); \
	MINOR=$$(echo "$$CURRENT" | cut -d. -f2); \
	PATCH=$$(echo "$$CURRENT" | cut -d. -f3); \
	case "$(BUMP)" in \
		major) MAJOR=$$((MAJOR + 1)); MINOR=0; PATCH=0 ;; \
		minor) MINOR=$$((MINOR + 1)); PATCH=0 ;; \
		patch) PATCH=$$((PATCH + 1)) ;; \
	esac; \
	NEW_TAG="v$${MAJOR}.$${MINOR}.$${PATCH}"; \
	DOCKER_IMAGE="$(REGISTRY)/$(NAME):$$NEW_TAG"; \
	DOCKER_LATEST="$(REGISTRY)/$(NAME):latest"; \
	echo ""; \
	echo "Bumping $$LATEST -> $$NEW_TAG ($(BUMP))"; \
	echo ""; \
	echo "==> Building Docker image $$DOCKER_IMAGE"; \
	docker build --tag "$$DOCKER_IMAGE" --tag "$$DOCKER_LATEST" .; \
	echo "==> Pushing $$DOCKER_IMAGE"; \
	docker push "$$DOCKER_IMAGE"; \
	echo "==> Pushing $$DOCKER_LATEST (-> $$NEW_TAG)"; \
	docker push "$$DOCKER_LATEST"; \
	echo ""; \
	echo "==> Tagging git $$NEW_TAG"; \
	git tag -a "$$NEW_TAG" -m "Release $$NEW_TAG"; \
	git push origin "$$NEW_TAG"; \
	echo ""; \
	echo "==> Release $$NEW_TAG created and pushed"; \
	echo ""

# ==============================================================================
# Code Quality & Security
# ==============================================================================

gosec: ## Run gosec security scanner
	gosec -color -tests ./...

staticcheck: ## Run staticcheck linter
	staticcheck ./...

vulncheck: ## Run vulnerability checker
	govulncheck -scan package ./...

fmt: ## Format code with gofumpt
	gofumpt -w .

# ==============================================================================
# Docker Compose Operations
# ==============================================================================

start: ## Start services with docker-compose
	$(info Starting mellon)
	docker compose -f docker-compose.yaml up -d --remove-orphans

stop: ## Stop services
	$(info Stopping mellon)
	docker compose -f docker-compose.yaml rm -s -f

restart: stop start ## Restart services
