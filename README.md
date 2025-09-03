<p align="center">
  <img width="120" height="120" alt="AppIcon" src="http://devrepo.victorlobe.me/packageIcons/iCloudMailFixIcon.png" />
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

## Overview

iOS 6 is no longer compatible with modern iCloud Mail servers due to outdated TLS protocols. This tweak solves this problem by:

1. **Intercepting** Mail app connections to iCloud servers
2. **Redirecting** them to a local proxy running on `127.0.0.1`
3. **Establishing** modern TLS connections to iCloud servers
4. **Proxying** data between the Mail app (plaintext) and iCloud (TLS)

## 🔨 Architecture
armv7 + arm64

iOS 6 Mail App (Plaintext) ↔ Local Proxy (127.0.0.1) ↔ iCloud Servers (TLS)


## ✨ Features

-  **Restores full functionality of Mail.app
-  **IMAP Support**: `imap.mail.me.com:993` → `127.0.0.1:143`
-  **SMTP Support**: `smtp.mail.me.com:587` → `127.0.0.1:587`
-  **Automatic Startup**: Runs as a LaunchDaemon
-  **Transparent Proxy**: No configuration required
-  **Modern TLS**: Uses mbedTLS for secure connections
- ⚠️ **Manual Account Only**: Currently only works with manually added iCloud Mail accounts (will be fixed in a later version)

## 🧰 Requirements

- **iOS Version**: iOS 6.0 or later
- **Dependencies**: mobilesubstrate, PreferenceLoader

## 🚀 Installation

### From Repository

1. Add the repository `repo.victorlobe.me` to Cydia
2. Search for "iCloudMailFix"
3. Install the package
4. Respring your device

### Manual Installation

1. Download the `.deb` file
2. Install using `dpkg -i iCloudMailFix.deb`
3. Respring your device

### Account Setup

**Important**: This tweak currently only works with **manually added iCloud Mail accounts**. The default iCloud Mail account from Settings → iCloud → Mail will not work.

To add a manual iCloud Mail account:
1. Open **Settings** → **Mail, Contacts, Calendars**
2. Tap **Add Account**
3. Select **Other**
4. Choose **Add Mail Account**
5. Enter your full **iCloud email** and **App Specific Password**

6. For **Incoming Mail Server**:
   - Host Name: `imap.mail.me.com`
   - Username: The **name part** of your mail address e.g. Tim.cook@icloud.com -> **Tim.cook**
   - Password: **Your App Specific Password**
   
7. For **Outgoing Mail Server**:
   - Host Name: `smtp.mail.me.com`
   - Username: Your **full** iCloud email e.g. **Tim.cook@icloud.com**
   - Password: **Your App Specific Password**
   
8. Tap **Save**

**Note**: Support for the default iCloud Mail account will be added in a future update.

# Technical Stuff

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
- ❌ **Read or store passwords** - Passwords are never processed or logged
- ❌ **Access external networks** - Only connects to localhost and iCloud
- ❌ **Modify email content** - Data is proxied transparently
- ❌ **Log sensitive data** - Only connection metadata is logged (and stays on your device)

### Security Considerations
- ⚠️ **TLS Validation**: Uses `MBEDTLS_SSL_VERIFY_OPTIONAL` for iOS 6 compatibility which is not secure but should be fine in your home network

### TLS Security
The tweak uses `MBEDTLS_SSL_VERIFY_OPTIONAL` instead of `REQUIRED` because:
- iOS 6 has outdated CA certificates (2012)
- Modern iCloud certificates would fail validation
- The local proxy + TLS to iCloud provides adequate security
- Functionality is prioritized over strict certificate validation

## 📸 Logs and Debugging

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

## Uninstallation

### From Cydia
1. Remove the package through Cydia
2. Respring your device

### Manual Removal
```bash
# Stop the daemon
launchctl unload /Library/LaunchDaemons/com.victorlobe.iCloudMailFix.plist

# Remove files
rm /usr/libexec/iCloudMailFixd
rm /Library/LaunchDaemons/com.victorlobe.iCloudMailFix.plist
rm /var/run/iCloudMailFixd.pid

# Remove logs (optional)
rm /var/log/iCloudMailFixd.err
rm /var/log/iCloudMailFixd.out
rm /var/log/iCloudMailFix-hook.log
```

## Technical Details

### Supported Protocols
- **IMAP**: `imap.mail.me.com:993` (TLS) → `127.0.0.1:143` (Plaintext)
- **SMTP**: `smtp.mail.me.com:587` (STARTTLS) → `127.0.0.1:587` (Plaintext)

### TLS Configuration
- **Library**: mbedTLS 3.x
- **Validation**: `MBEDTLS_SSL_VERIFY_OPTIONAL`
- **Ciphers**: Default mbedTLS preset
- **SNI**: Enabled for proper hostname validation

## Version History

### v1.0.0
- Initial release
- IMAP and SMTP support
- Local TLS proxy implementation
- Automatic startup via LaunchDaemon
- Manual iCloud Mail account support only

## 🗒️ To Do

- [ ] **Default iCloud Account Support**:
- [ ] **Add some settings**:

**Note**: Features are prioritized based on user feedback and technical feasibility.

## 👨‍💻 Author

Made with ❤️ by Victor Lobe

## 📄 License

MIT License – Free to use, share, and modify.

## 🚨 Disclaimer

This tweak is designed for educational and compatibility purposes. Use at your own risk. The developer is not responsible for any data loss or security issues that may arise from using this software.
