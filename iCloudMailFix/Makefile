ARCHS = armv7 arm64
TARGET := iphone:7.1

include $(THEOS)/makefiles/common.mk

# ---- Tweak (DNS redirect) ----
TWEAK_NAME = iCloudMailFix
iCloudMailFix_FILES = Tweak.xm
iCloudMailFix_LIBRARIES = substrate
iCloudMailFix_CFLAGS = -fobjc-arc
iCloudMailFix_FRAMEWORKS = CoreFoundation CFNetwork Security

include $(THEOS_MAKE_PATH)/tweak.mk

# ---- Tool (daemon) ----
TOOL_NAME = iCloudMailFixd
iCloudMailFixd_INSTALL_PATH = /usr/libexec

MBEDTLS_DIR = vendor/mbedtls
MBEDTLS_SRCS = $(wildcard $(MBEDTLS_DIR)/library/*.c)

iCloudMailFixd_FILES  = src/iCloudMailFixd.c $(MBEDTLS_SRCS)
iCloudMailFixd_CFLAGS += -I$(MBEDTLS_DIR)/include -DMBEDTLS_CONFIG_FILE='<mbedtls/config.h>'

include $(THEOS_MAKE_PATH)/tool.mk

after-stage::
	# LaunchDaemon
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/Library/LaunchDaemons$(ECHO_END)
	$(ECHO_NOTHING)cp layout/Library/LaunchDaemons/com.victorlobe.iCloudMailFix.plist $(THEOS_STAGING_DIR)/Library/LaunchDaemons/$(ECHO_END)

	# DEBIAN maintainer scripts
	$(ECHO_NOTHING)mkdir -p $(THEOS_STAGING_DIR)/DEBIAN$(ECHO_END)
	$(ECHO_NOTHING)cp postinst $(THEOS_STAGING_DIR)/DEBIAN/postinst$(ECHO_END)
	$(ECHO_NOTHING)cp prerm   $(THEOS_STAGING_DIR)/DEBIAN/prerm$(ECHO_END)
	$(ECHO_NOTHING)chmod 755 $(THEOS_STAGING_DIR)/DEBIAN/postinst $(THEOS_STAGING_DIR)/DEBIAN/prerm$(ECHO_END)
	
after-package::
	@if [ "$(RELEASE_MODE)" = "1" ]; then \
		echo "[🚀] Release build - skipping dev pipeline"; \
	else \
		echo "[📦] Running deployment pipeline..."; \
		DEB="$$(ls -t "$(THEOS_PACKAGE_DIR)"/*.deb | head -1)"; \
		if [ -z "$$DEB" ] || [ ! -f "$$DEB" ]; then echo "[❌] No .deb found in $(THEOS_PACKAGE_DIR)"; exit 1; fi; \
		echo "[ℹ️ ] Found latest package: $$DEB"; \
		BASE="$$(basename "$$DEB" .deb)"; \
		TMP="$${BASE#*_}"; \
		VERSION="$${TMP%_*}"; \
		echo "[ℹ️ ] Extracted version: $$VERSION"; \
		echo "[📦] Creating git commit..."; \
		git add -A; \
		if git commit -m "Build $$VERSION"; then echo "[✅] Commit successful: Build $$VERSION"; else echo "[⚠️ ] Nothing to commit"; fi; \
		DEST="/Volumes/victor/Sites/repo-dev/debs"; \
		echo "[📂] Copying $$DEB to $$DEST..."; \
		mkdir -p "$$DEST"; cp -v "$$DEB" "$$DEST/"; echo "[✅] Copied successfully"; \
		echo "[⚙️ ] Running Update.sh in /Volumes/victor/Sites/repo-dev..."; \
		cd /Volumes/victor/Sites/repo-dev; \
		if [ -x ./Update.sh ]; then ./Update.sh; elif [ -f ./Update.sh ]; then /bin/bash ./Update.sh; else echo "[⚠️ ] Warning: Update.sh not found"; fi; \
		echo "[✅] Update.sh finished"; \
		MSG="Built $$VERSION and updated repo"; echo "[🔔] macOS notification: $$MSG"; \
		/usr/bin/osascript -e "display notification \"$$MSG\" with title \"iCloudMailFix Build\" subtitle \"Deployment complete\"" \
		&& echo "[✅] Notification sent" || echo "[⚠️ ] Could not display notification"; \
	fi

# ---- Release target (no dev pipeline) ----
release::
	@echo "[🚀] Building release version..."
	@$(MAKE) package RELEASE_MODE=1
	@echo "[✅] Release package built successfully"
	@echo "[📦] Package location: $(THEOS_PACKAGE_DIR)"
	@echo "[📋] Manual deployment required"
SUBPROJECTS += iCloudMailFixPrefs
include $(THEOS_MAKE_PATH)/aggregate.mk
