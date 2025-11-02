# slipstream-deploy

🚀 **One-click slipstream server deployment and management**

A comprehensive automation script for deploying and managing [slipstream](https://endpositive.github.io/slipstream/) DNS tunnel servers on Linux systems. This script handles everything from installation to configuration, making DNS tunnel deployment effortless.

## DNS Domain Setup

Before using this script, you need to properly configure your domain's DNS records. Here's the required setup:

### Example Configuration
- **Your domain name**: `example.com`
- **Your server's IPv4 address**: `203.0.113.2`
- **Tunnel subdomain**: `s.example.com`
- **Server hostname**: `ns.example.com`

### DNS Records Setup
Go into your name registrar's configuration panel and add these records:

| Type | Name | Points to |
|------|------|-----------|
| A | `ns.example.com` | `203.0.113.2` |
| NS | `s.example.com` | `ns.example.com` |

**Important**: Wait for DNS propagation (can take up to 24 hours) before testing your tunnel.

## Features

- **Multi-distribution support**: Fedora, Rocky Linux, CentOS, Debian, Ubuntu
- **Interactive management menu**: Easy-to-use interface for all operations
- **Self-updating capability**: Built-in update mechanism for the script
- **Automatic detection**: OS and SSH port detection
- **Systemd service integration**: Creates and manages a dedicated systemd service for reliable operation, automatic startup on boot, and comprehensive logging
- **Security hardened**: Non-root service execution with systemd security features
- **Smart configuration**: Persistent settings and automatic key reuse
- **Flexible tunneling**: SSH mode or SOCKS proxy mode
- **Network ready**: Automatic firewall and iptables configuration
- **Binary verification**: MD5, SHA1, and SHA256 checksum validation
- **Official binaries**: Downloads from [slipstream/releases](https://github.com/EndPositive/slipstream/releases/)
