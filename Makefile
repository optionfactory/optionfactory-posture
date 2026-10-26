REPO_OWNER=optionfactory
REPO_NAME=optionfactory-posture


build:
	@cargo build

build-release:
	@cargo build --release --target x86_64-unknown-linux-musl

test:
	@cargo test

clean:
	-@rm -rf target/

publish-github: build-release
	$(eval VERSION=v$(shell cargo metadata --format-version=1 --no-deps | jq -r '.packages[0].version'))
	@cp target/x86_64-unknown-linux-musl/release/$(REPO_NAME) target/$(REPO_NAME)-linux-amd64-musl
	@cd target && sha256sum $(REPO_NAME)-linux-amd64-musl > SHA256SUMS
	@gh release create "$(VERSION)" \
		"target/$(REPO_NAME)-linux-amd64-musl" \
		"target/SHA256SUMS" \
		--repo "$(REPO_OWNER)/$(REPO_NAME)" \
		--title "$(VERSION)" \
		--target "master" \
		--notes ""
	-@rm target/$(REPO_NAME)-linux-amd64-musl target/SHA256SUMS

.PHONY: build build-release test clean publish-github
