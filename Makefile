EXT_DIR := vscode-authz
EXT_ID := oarkflow.authz-dsl
CODE ?= code
VSCE ?= vsce
PNPM ?= pnpm
SAMPLE ?= examples/config.authz

VERSION := $(shell node -p "require('./$(EXT_DIR)/package.json').version")
VSIX := $(EXT_DIR)/authz-dsl-$(VERSION).vsix

ifeq ($(OS),Windows_NT)
HOST_OS := windows
else
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
HOST_OS := macos
else
HOST_OS := linux
endif
endif

.PHONY: all authz-ext-build authz-ext-install authz-ext-open authz-ext-reload authz-ext-dev authz-ext-status

all: authz-ext-dev

authz-ext-build:
	cd $(EXT_DIR) && $(PNPM) exec $(VSCE) package --allow-missing-repository --no-dependencies

install-extension: authz-ext-build
	$(CODE) --install-extension $(VSIX) --force

authz-ext-open:
	$(CODE) --reuse-window $(SAMPLE)

authz-ext-reload:
ifeq ($(HOST_OS),macos)
	@open -a "Visual Studio Code"
	@osascript \
		-e 'delay 0.4' \
		-e 'tell application "System Events" to keystroke "r" using {command down}' \
		|| printf '%s\n' 'VS Code reload was blocked by macOS Accessibility permissions. Allow your terminal to control the computer, or run Developer: Reload Window manually.'
else ifeq ($(HOST_OS),windows)
	@powershell -NoProfile -ExecutionPolicy Bypass -Command "$$wshell = New-Object -ComObject WScript.Shell; $$wshell.AppActivate('Visual Studio Code') | Out-Null; Start-Sleep -Milliseconds 400; $$wshell.SendKeys('^r')" \
		|| echo VS Code reload was blocked. Run Developer: Reload Window manually.
else
	@if command -v xdotool >/dev/null 2>&1; then \
		$(CODE) --reuse-window $(SAMPLE); \
		sleep 0.4; \
		xdotool key ctrl+r; \
	else \
		printf '%s\n' 'Install xdotool for automatic VS Code reload on Linux, or run Developer: Reload Window manually.'; \
	fi
endif

authz-ext-dev: authz-ext-install authz-ext-open authz-ext-reload

authz-ext-status:
	$(CODE) --list-extensions --show-versions | node -e "const fs=require('fs'); const id='$(EXT_ID)@'; const line=fs.readFileSync(0,'utf8').split(/\r?\n/).find((entry)=>entry.startsWith(id)); if (line) console.log(line);"
