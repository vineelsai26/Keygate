APP_NAME      := Keygate
DISPLAY_NAME  := Keygate
BUNDLE_ID     := dev.vstack.keygate
EXEC          := KeygateApp
CLI           := keygate
CONFIG        := release
SIGN_IDENTITY := Keygate Local Signing

BUILD_DIR     := .build/$(CONFIG)
DIST          := dist
APP           := $(DIST)/$(APP_NAME).app
CONTENTS      := $(APP)/Contents
MACOS         := $(CONTENTS)/MacOS
RESOURCES     := $(CONTENTS)/Resources

.PHONY: all app build cli bundle sign run selftest clean

all: app

build:
	swift build -c $(CONFIG)

selftest:
	swift run keygate-selftest

app: bundle sign
	@echo "Built $(APP)"

bundle: build
	@rm -rf "$(APP)"
	@mkdir -p "$(MACOS)" "$(RESOURCES)"
	@cp "$(BUILD_DIR)/$(EXEC)" "$(MACOS)/$(EXEC)"
	@cp Resources/Info.plist "$(CONTENTS)/Info.plist"
	@if [ -f Resources/AppIcon.icns ]; then cp Resources/AppIcon.icns "$(RESOURCES)/AppIcon.icns"; fi
	@printf 'APPL????' > "$(CONTENTS)/PkgInfo"
	@echo "Assembled $(APP)"

sign:
	@if security find-identity -p codesigning 2>/dev/null | grep -qF "$(SIGN_IDENTITY)"; then \
		echo "Signing with '$(SIGN_IDENTITY)' (local entitlements, no iCloud)"; \
		codesign --force --sign "$(SIGN_IDENTITY)" --entitlements Resources/entitlements-local.plist --timestamp=none "$(APP)"; \
	else \
		echo "No '$(SIGN_IDENTITY)' identity — signing ad-hoc without CloudKit entitlements."; \
		codesign --force --sign - --timestamp=none "$(APP)"; \
	fi
	@codesign --verify --verbose "$(APP)" && echo "Signed: $(APP)"

cli: build
	@mkdir -p "$(DIST)"
	@cp "$(BUILD_DIR)/$(CLI)" "$(DIST)/$(CLI)"
	@if security find-identity -p codesigning 2>/dev/null | grep -qF "$(SIGN_IDENTITY)"; then \
		echo "Signing CLI with '$(SIGN_IDENTITY)' so it shares the app's Keychain identity"; \
		codesign --force --sign "$(SIGN_IDENTITY)" --timestamp=none "$(DIST)/$(CLI)"; \
	fi
	@echo "CLI at $(DIST)/$(CLI)"

run: app
	@open "$(APP)"

clean:
	swift package clean
	@rm -rf "$(DIST)"
