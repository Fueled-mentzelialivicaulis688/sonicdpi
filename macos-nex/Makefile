# SonicDPI macOS NetworkExtension build harness.
#
# Builds:
#   1. libsonicdpi_macos_nex.dylib  (universal arm64 + x86_64)
#   2. SonicDPIExtension.systemextension  (Swift NEFilterPacketProvider)
#   3. SonicDPI.app  (host app, packages the .systemextension inside)
#
# Requires:
#   - Xcode + command-line tools
#   - Apple Developer ID Application certificate (for codesign)
#   - Apple-granted entitlement `com.apple.developer.networking.networkextension`
#     (request via developer.apple.com — Apple reviews case-by-case)
#   - Notarization profile in `xcrun notarytool` keychain (for distribution)
#
# Variables you must set before `make`:
#   DEVELOPER_ID  — e.g. "Developer ID Application: Your Name (TEAMID)"
#   TEAM_ID       — your 10-char Apple Team ID, e.g. "ABCDE12345"
#
# Quick:
#   make build       — compile + bundle (unsigned, won't load)
#   make sign        — codesign with $DEVELOPER_ID
#   make notarize    — submit to Apple notary (needs prior `notarytool store-credentials`)
#   make install     — copy to /Applications and launch the host app once
#   make clean

DYLIB_NAME = libsonicdpi_macos_nex.dylib
DYLIB_DIR  = ../target/universal/release
APP_NAME   = SonicDPI.app
SX_NAME    = SonicDPIExtension.systemextension
BUILD_DIR  = build

DEVELOPER_ID ?= -
TEAM_ID      ?= TEAMID

.PHONY: all build dylib sx app sign notarize install clean

all: build

build: dylib sx app

dylib:
	@echo "==> Building Rust dylib (universal)"
	@cd .. && cargo build --release -p sonicdpi-macos-nex --target aarch64-apple-darwin
	@cd .. && cargo build --release -p sonicdpi-macos-nex --target x86_64-apple-darwin
	@mkdir -p $(DYLIB_DIR)
	@lipo -create \
		../target/aarch64-apple-darwin/release/$(DYLIB_NAME) \
		../target/x86_64-apple-darwin/release/$(DYLIB_NAME) \
		-output $(DYLIB_DIR)/$(DYLIB_NAME)
	@echo "    -> $(DYLIB_DIR)/$(DYLIB_NAME)"

sx: dylib
	@echo "==> Building System Extension bundle"
	@mkdir -p $(BUILD_DIR)/$(SX_NAME)/Contents/MacOS
	@mkdir -p $(BUILD_DIR)/$(SX_NAME)/Contents/Frameworks
	@swiftc Extension/PacketFilterProvider.swift \
		-import-objc-header /dev/null \
		-target arm64-apple-macosx13.0 \
		-target x86_64-apple-macosx13.0 \
		-emit-executable \
		-o $(BUILD_DIR)/$(SX_NAME)/Contents/MacOS/SonicDPIExtension \
		-L$(DYLIB_DIR) -lsonicdpi_macos_nex \
		-Xlinker -rpath -Xlinker @executable_path/../Frameworks
	@cp $(DYLIB_DIR)/$(DYLIB_NAME) $(BUILD_DIR)/$(SX_NAME)/Contents/Frameworks/
	@cp Extension/Info.plist $(BUILD_DIR)/$(SX_NAME)/Contents/Info.plist
	@echo "    -> $(BUILD_DIR)/$(SX_NAME)"

app: sx
	@echo "==> Building host .app"
	@mkdir -p $(BUILD_DIR)/$(APP_NAME)/Contents/MacOS
	@mkdir -p $(BUILD_DIR)/$(APP_NAME)/Contents/Library/SystemExtensions
	@swiftc HostApp/HostAppMain.swift \
		-target arm64-apple-macosx13.0 \
		-target x86_64-apple-macosx13.0 \
		-emit-executable \
		-o $(BUILD_DIR)/$(APP_NAME)/Contents/MacOS/SonicDPIHost
	@cp HostApp/Info.plist $(BUILD_DIR)/$(APP_NAME)/Contents/Info.plist
	@cp -R $(BUILD_DIR)/$(SX_NAME) $(BUILD_DIR)/$(APP_NAME)/Contents/Library/SystemExtensions/
	@echo "    -> $(BUILD_DIR)/$(APP_NAME)"

sign:
	@echo "==> Codesigning with $(DEVELOPER_ID)"
	@codesign --force --options runtime \
		--entitlements Extension/Extension.entitlements \
		--sign "$(DEVELOPER_ID)" \
		$(BUILD_DIR)/$(APP_NAME)/Contents/Library/SystemExtensions/$(SX_NAME)
	@codesign --force --options runtime \
		--entitlements HostApp/HostApp.entitlements \
		--sign "$(DEVELOPER_ID)" \
		$(BUILD_DIR)/$(APP_NAME)
	@codesign --verify --deep --strict --verbose=2 $(BUILD_DIR)/$(APP_NAME)

notarize:
	@echo "==> Notarizing"
	@ditto -c -k --keepParent $(BUILD_DIR)/$(APP_NAME) $(BUILD_DIR)/SonicDPI.zip
	@xcrun notarytool submit $(BUILD_DIR)/SonicDPI.zip \
		--keychain-profile sonicdpi-notary --wait
	@xcrun stapler staple $(BUILD_DIR)/$(APP_NAME)

install:
	@echo "==> Installing to /Applications and launching"
	@rm -rf /Applications/$(APP_NAME)
	@cp -R $(BUILD_DIR)/$(APP_NAME) /Applications/
	@open /Applications/$(APP_NAME)
	@echo "    System Settings → Privacy & Security → Allow SonicDPI Extension"

clean:
	rm -rf $(BUILD_DIR) $(DYLIB_DIR)
	cd .. && cargo clean -p sonicdpi-macos-nex
