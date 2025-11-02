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
- **Official binaries**: Downloads from [slipstream/releases](https://github.com/EndPositive/slipstream/releases/)

## Quick Start

### Prerequisites
- Linux server (Fedora, Rocky, CentOS, Debian, or Ubuntu)
- Root access or sudo privileges
- Internet connection for package downloads
- **Domain name with proper DNS configuration** (see DNS Domain Setup section above)

### Installation

**One-command installation:**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/squirtea/slipstream-deploy/main/slipstream-deploy.sh)
```

This command will:
1. Download and install the script to `/usr/local/bin/slipstream-deploy`
2. Start the interactive setup process
3. Configure your slipstream server automatically

### Post-Installation Usage

After installation, you can manage your slipstream server using the installed command:

```bash
slipstream-deploy
```

This will show an interactive menu with these options:

1. **Install/Reconfigure slipstream server** - Set up or modify configuration
2. **Update slipstream-deploy script** - Check for and install script updates
3. **Check service status** - View current service status
4. **View service logs** - Monitor real-time logs (Ctrl+C to exit)
5. **Exit** - Quit the menu

### Setup Process

During the setup (option 1), you'll be prompted for:
- **Nameserver subdomain** (e.g., `s.example.com`)
- **Tunnel mode** (SSH or SOCKS)

## Configuration

### Tunnel Modes

**SOCKS Mode (Option 1)**
- Sets up integrated Dante SOCKS5 proxy
- Listens on `127.0.0.1:1080`
- Provides full internet proxy capabilities

**SSH Mode (Option 2)**
- Tunnels DNS traffic to your SSH service
- Automatically detects SSH port (default: 22)
- Perfect for secure shell access via DNS
- Compatible with mobile apps

### Changing Settings
To change settings:
1. Run `slipstream-deploy`
2. Choose option 1 (Install/Reconfigure slipstream server)
3. Enter new values when prompted

The script will automatically update the configuration and restart services.

## Management

### Management Menu

The easiest way to manage your slipstream server is through the interactive menu:

```bash
slipstream-deploy
```

This provides quick access to:
- Server reconfiguration
- Script updates
- Service status monitoring
- Real-time log viewing

### File Locations

```
/usr/local/bin/slipstream-deploy             # Management script
/usr/local/bin/slipstream-server             # Main binary
/etc/slipstream/                             # Configuration directory
├── slipstream-server.conf                  # Main configuration
├── {domain}_server.key                # Private key (per domain)
└── {domain}_server.pub                # Public key (per domain)
/etc/systemd/system/slipstream-server.service  # Systemd service
```

### Manual Service Commands

If you prefer command-line management:

**slipstream-server Service**:
```bash
sudo systemctl status slipstream-server    # Check status
sudo systemctl start slipstream-server     # Start service
sudo systemctl stop slipstream-server      # Stop service
sudo systemctl restart slipstream-server   # Restart service
sudo journalctl -u slipstream-server -f    # View logs
```

**Dante SOCKS Service (SOCKS mode only)**:
```bash
sudo systemctl status danted          # Check status
sudo systemctl start danted           # Start service
sudo systemctl stop danted            # Stop service
sudo systemctl restart danted         # Restart service
sudo journalctl -u danted -f          # View logs
```

### Updating the Script

The script can update itself in two ways:

**Method 1: Using the menu (recommended)**
```bash
slipstream-deploy
# Choose option 2: Update slipstream-deploy script
```

**Method 2: Re-run the curl command**
```bash
bash <(curl -Ls https://raw.githubusercontent.com/squirtea/slipstream-deploy/main/slipstream-deploy.sh)
# The script will detect and install updates automatically
```

## Troubleshooting

### Using the Built-in Tools

The management menu provides quick access to troubleshooting tools:

1. **Check service status** (menu option 3): Shows if services are running properly
2. **View service logs** (menu option 4): Real-time monitoring of service logs

### Common Issues

**Service Won't Start**:
```bash
slipstream-deploy  # Use menu option 3 to check status
# Or manually:
sudo systemctl status slipstream-server    # Check service status
sudo journalctl -u slipstream-server -n 50 # Check logs for errors
ls -la /usr/local/bin/slipstream-server    # Verify binary permissions
```

**DNS Configuration Issues**:
```bash
dig @YOUR_SERVER_IP s.mydomain.com           # Test DNS tunnel (from client)
sudo iptables -t nat -L PREROUTING -n -v     # Check iptables rules
```

**SOCKS Proxy Issues**:
```bash
curl --socks5 127.0.0.1:1080 http://httpbin.org/ip  # Test SOCKS proxy locally
sudo cat /etc/danted.conf                           # Check Dante configuration
```

**Port Check**:
```bash
sudo ss -tulnp | grep 5300  # Check slipstream-server port
sudo ss -tulnp | grep 1080  # Check SOCKS proxy port (if enabled)
```

## Advanced Features

### Performance Monitoring

Use the built-in log viewer (menu option 4) or manual commands:

```bash
sudo ss -tulnp | grep -E "(5300|1080)"        # Monitor connection count
sudo systemctl status slipstream-server            # Check service resources
sudo journalctl -u slipstream-server -f --no-pager # Monitor logs for errors
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## Acknowledgments

- [dnstt](https://dnstt.network) by David Fifield
- [slipstream](https://github.com/EndPositive/slipstream) by Jop Zitman
- [dnstt-deploy](https://github.com/bugfloyd/dnstt-deploy) by Yashar Hosseinpour
- [Dante SOCKS server](https://www.inet.no/dante/) for SOCKS proxy functionality

---

**Made with ❤️ for privacy and security**
