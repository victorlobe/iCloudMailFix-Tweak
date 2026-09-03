<p align="center">
  <img width="120" height="120" alt="iCloudMailFixIcon" src="https://github.com/user-attachments/assets/fc6d260c-7d25-42a3-81ef-a941cd24d6dd" />
</p>

<h1 align="center">iCloudMailFix</h1>

<p align="center">
  A jailbreak tweak that fixes iCloud Mail functionality on iOS 6 and newer by implementing a local TLS proxy.
</p>

<p align="center">
  <a href="https://github.com/victorlobe/iCloudMailFix/releases/latest">
    <img alt="Download" src="https://img.shields.io/badge/download-latest-blue?logo=apple" />
  </a>
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green">
  <img alt="Platform" src="https://img.shields.io/badge/platform-iOS%206-007AFF">
</p>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Quick Start](#-quick-start)
- [Features](#-features)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Setup](#-setup)
- [Changelog](#-changelog)
- [Technical Details](#-technical-details)
- [Troubleshooting](#-troubleshooting)
- [Uninstallation](#-uninstallation)
- [Credits](#-credits)
- [To Do](#-to-do)
- [License](#-license)
- [Disclaimer](#-disclaimer)
- [Author](#-author)

---

## 📖 Overview

iOS 6 is no longer compatible with modern iCloud Mail servers due to outdated TLS protocols. This tweak solves this problem by:

1. **Intercepting** Mail app connections to iCloud servers
2. **Redirecting** them to a local proxy running on `127.0.0.1`
3. **Establishing** modern TLS connections to iCloud servers
4. **Proxying** data between the Mail app (plaintext) and iCloud (TLS)

## 🚀 Quick Start

1. **Install** the tweak from `repo.victorlobe.me`
2. **Add** your iCloud Mail account manually in Settings → Mail, Contacts, Calendars (see Settings → iCloud Mail Fix → Instructions)
3. **Enjoy** working Mail app on iOS 6!

## ⚙️ Setup

1. Open **Settings** → **Mail, Contacts, Calendars**
2. Tap **Add Account**
3. Select **Other**
4. Choose **Add Mail Account**
5. Enter your full **iCloud email** and **App Specific Password**

6. For **Incoming Mail Server**:
   - Host Name: `imap.mail.me.com`
   - Username: The **name part** of your mail address e.g. John.ternus@icloud.com → **John.ternus**
   - Password: **Your App Specific Password**
   
7. For **Outgoing Mail Server**:
   - Host Name: `smtp.mail.me.com`
   - Username: Your **full** iCloud email e.g. **John.ternus@icloud.com**
   - Password: **Your App Specific Password**
   
8. Tap **Save**
9. It might take a while. Be patient. When asked if you want to set up the account without SSL, select **No SSL**. After that, an error will appear — this is normal. Just tap **Continue**.
10. Done

If you experience problems, check that the following ports are configured:
- **Incoming mail (IMAP)**: `143`
- **Outgoing mail (SMTP)**: `587`

**Note**: This tweak currently only works with manually added iCloud Mail accounts. The default iCloud Mail account from Settings → iCloud → Mail will not work. Support for the default iCloud Mail account will be added in a future update.

## ✨ Features

-  **Restores full functionality of Mail.app**
-  **IMAP Support**: `imap.mail.me.com:993` → `127.0.0.1:143`
-  **SMTP Support**: `smtp.mail.me.com:587` → `127.0.0.1:587`
-  **Automatic Startup**: Runs as a LaunchDaemon
-  **Modern TLS**: Uses mbedTLS for secure connections
-  **iCloud Notes**: Supports syncing iCloud Notes
-  **Sparrow Support**: Works with the Sparrow mail client
-  **TLS Certificate Validation**: Enabled by default and can be disabled for compatibility
-  **CA Bundle Updates**: Update the CA certificate bundle directly from the device through Settings
- ⚠️ **Manual Account Only**: Currently only works with manually added iCloud Mail accounts (will be fixed in a later version)

## 📋 Requirements

- **iOS Version**: iOS 6.0 or later
- **Dependencies**: mobilesubstrate, PreferenceLoader

## 📦 Installation

### From Repository

1. Add the repository `repo.victorlobe.me` to Cydia
2. Search for "iCloudMailFix"
3. Install the package
4. Respring your device

# 📝 Changelog

### v2.0.0
- Added support for syncing iCloud Notes
- Added support for the Sparrow mail client
- Added optional TLS certificate validation, enabled by default for improved security
- Added CA certificate bundle updates via settings
- Huge thanks to Jeffrey Bergier ([@jeffreybergier](https://github.com/jeffreybergier) on GitHub) for contributing Notes synchronization, CA certificate validation, and Sparrow support through pull requests #4, #5, and #6.

### v1.0.2
- Changed contact email address in the control file

### v1.0.1
- Fixed the preference bundle on arm64 devices
- Modified the Instructions

### v1.0.0
- Initial release
- IMAP and SMTP support
- Local TLS proxy implementation
- Automatic startup via LaunchDaemon
- Manual iCloud Mail account support only

# 🔧 Technical Details

## 🔨 Architecture
armv7 + arm64

iOS 6 Mail App (Plaintext) ↔ Local Proxy (127.0.0.1) ↔ iCloud Servers (TLS)

## 🧠 Behind the Scenes

### DNS Hook (Tweak.xm)
- Hooks `getaddrinfo()` and `CFStreamCreatePairWithSocketToHost()`
- Redirects iCloud Mail hostnames to `127.0.0.1`
- Blocks SSL/TLS attempts from the Mail app

### Proxy Daemon (iCloudMailFixd)
- Listens on `127.0.0.1:143` (IMAP) and `127.0.0.1:587` (SMTP)
- Establishes TLS connections to real iCloud servers
- Proxies data transparently between client and server

## 🛑 Security Notes

### What This Tweak Does NOT Do
- ❌ **Access sensitive data** - Passwords are never processed, stored, or logged. Only connection metadata is logged locally.

### Security Considerations
- ⚠️ **TLS Validation**: Certificate validation is enabled by default and uses the CA bundle installed by iCloudMailFix. It can be disabled in Settings → iCloud Mail Fix for compatibility troubleshooting.

### TLS Security
The tweak uses `MBEDTLS_SSL_VERIFY_OPTIONAL` for iOS 6 compatibility. The CA bundle can be updated from Settings → iCloud Mail Fix → Update CA certificate bundle. The downloaded bundle is validated before it replaces the active local override.

### Supported Protocols
- **IMAP**: `imap.mail.me.com:993` (TLS) → `127.0.0.1:143` (Plaintext)
- **SMTP**: `smtp.mail.me.com:587` (STARTTLS) → `127.0.0.1:587` (Plaintext)

### TLS Configuration
- **Library**: mbedTLS 3.x
- **Validation**: `MBEDTLS_SSL_VERIFY_OPTIONAL`
- **Default**: Certificate validation enabled
- **Ciphers**: Default mbedTLS preset
- **SNI**: Enabled for proper hostname validation

## 📊 Logs and Debugging

### Log Files
- **Daemon Logs (Main Log)**: `/var/log/iCloudMailFixd.err`
- **Hook Logs (isn´t really used)**: `/var/log/iCloudMailFix-hook.log`
- **Package Logs**: `/var/log/iCloudMailFixd.pkg.log`

## 🐞 Troubleshooting

### Mail App Still Not Working
1. **Check if daemon is running**:
   ```bash
   launchctl list | grep iCloudMailFix
   ```

2. **Check logs for errors**:
   ```bash
   tail -f /var/log/iCloudMailFixd.err
   ```

3. **Restart the daemon**:
   ```bash
   launchctl unload /Library/LaunchDaemons/com.victorlobe.iCloudMailFix.plist
   launchctl load /Library/LaunchDaemons/com.victorlobe.iCloudMailFix.plist
   ```

### Connection Issues
- **Port conflicts**: Ensure ports 143 and 587 are not used by other services
- **Firewall**: Check if any firewall is blocking localhost connections (unlikely)
- **Network**: Verify internet connectivity for iCloud server connections (obviously)
- **Certificate errors**: In Settings → iCloud Mail Fix, update the CA certificate bundle and verify that certificate validation is enabled

### CA Bundle Update Issues
- Make sure the device has an active internet connection
- Leave the update alert open until it reports success or failure
- If the update fails, the previous CA bundle remains active

## 🗑️ Uninstallation
1. Remove the package through Cydia
2. Respring your device

## 👨‍💻 Credits

Huge thanks to Jeffrey Bergier ([@jeffreybergier](https://github.com/jeffreybergier) on GitHub) for contributing Notes synchronization, CA certificate validation, and Sparrow support through pull requests #4, #5, and #6.

## 🗒️ To Do

- [ ] **Default iCloud Account Support**
- [ ] **Support for more iOS Versions**
  - [ ] **iOS 5**
  - [ ] **iOS 8** 

## 📄 License

MIT License – Free to use, share, and modify.

## 🚨 Disclaimer

This tweak is designed for educational and compatibility purposes. Use at your own risk. The developer is not responsible for any data loss or security issues that may arise from using this software.

## 👨‍💻 Author

Made with ❤️ by Victor Lobe
