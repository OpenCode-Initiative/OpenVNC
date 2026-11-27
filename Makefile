# Publicacao do OpenVNC.
#
#   make all            gera todos os pacotes em dist/
#   make release        make all + cria a release vVERSION no GitHub com dist/*
#   make windows|linux|macos|android|ios   uma plataforma so
#
# A versao vem do arquivo VERSION (ou: make all VERSION=0.5.0).
# Requisitos por plataforma: ver packaging/README.md.

SHELL := bash
.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

VERSION ?= $(shell cat VERSION)
DIST    := dist

.PHONY: all release windows linux macos android ios clean check-tag

all: windows linux macos android ios
	@echo "==> pacotes em $(DIST)/:"; ls -la $(DIST)

windows:
	bash packaging/windows/build.sh "$(VERSION)" "$(DIST)"

linux:
	bash packaging/linux/build.sh "$(VERSION)" "$(DIST)"

macos:
	DEST="$(DIST)" bash packaging/macos/build-remote.sh "$(VERSION)"

android:
	bash packaging/android/build.sh "$(VERSION)" "$(DIST)"

ios:
	bash packaging/ios/build.sh "$(VERSION)" "$(DIST)"

check-tag:
	@git diff --quiet HEAD || { echo "ha mudancas nao commitadas: commite antes de publicar"; exit 1; }
	git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null || git tag "v$(VERSION)"
	git push origin HEAD "v$(VERSION)"

release: check-tag all
	gh release view "v$(VERSION)" >/dev/null 2>&1 \
	  && gh release upload "v$(VERSION)" $(DIST)/*-$(VERSION)* --clobber \
	  || gh release create "v$(VERSION)" $(DIST)/*-$(VERSION)* --title "OpenVNC $(VERSION)" --generate-notes

clean:
	rm -rf $(DIST)
