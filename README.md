<h1 align="center">ShellCrash</h1>

<p align="center">
  <a target="_blank" href="https://github.com/MetaCubeX/mihomo/releases">
    <img src="https://img.shields.io/github/release/MetaCubeX/mihomo.svg?style=flat-square&label=Core">
  </a>
  <a target="_blank" href="https://github.com/juewuy/ShellCrash/releases">
    <img src="https://img.shields.io/github/release/juewuy/ShellCrash.svg?style=flat-square&label=ShellCrash&colorB=green">
  </a>
</p>

<p align="center">
  <strong>A powerful script tool for the convenient deployment and management of mihomo/sing-box kernels in Shell environments.</strong>
</p>

<p align="center">
  <a href="README_CN.md">简体中文</a> | English
</p>

---

## :rocket: Core Features

- **Multi-Kernel Support**: Easily manage and switch between **mihomo** and **sing-box** kernels directly within the Shell environment.
- **Flexible Configuration Management**: Supports online import of subscription links and configuration files to simplify the setup process.
- **Automated Tasks**: Configure scheduled tasks for automatic updates of configuration files and rules.
- **Graphical Dashboard**: Support for online installation and use of local Web Dashboards to intuitively manage built-in rules and traffic.
- **Multiple Operation Modes**: Supports switching between various traffic forwarding modes, including Router mode and Local mode.
- **One-Click Maintenance**: Built-in online update functionality to keep the script and features up to date.

## :computer: Device Support

ShellCrash is designed to be compatible with the vast majority of network devices based on the Linux kernel:

* **Router Devices**: Supports various firmwares based on OpenWrt or its derivatives (e.g., Xiaomi, Netgear etc.).
* **Linux Servers**: Supports devices running standard Linux/GNU distributions (e.g., Debian, CentOS, Armbian, Ubuntu, etc.).
* **Third-Party Firmware**: Compatible with Padavan (Conservative Mode), Pandora, and ASUS/Merlin firmware.
* **Other Devices**: Compatible with other devices based on Linux/GNU or Linux/busybox.
* **Docker**：Compatible with Docker environments (e.g., Synology, PVE, etc.).

> For additional device support, please submit an [Issue](https://github.com/juewuy/ShellCrash/issues) or provide feedback in the [Telegram Group](https://t.me/ShellClash) (please include the device model and the output of the `uname -a` command).

---

## :hammer_and_wrench: Installation Guide

> [!TIP]
> If you encounter connection failures or SSL-related issues, please try switching to an alternative installation mirror.

### Prerequisites
1. Ensure the device has **SSH** enabled and **Root privileges** obtained (Linux systems with a GUI can use the terminal directly).
2. Connect to the device using an SSH tool (such as PuTTY, JuiceSSH, or the system's built-in terminal).

### :penguin: Standard Linux Device Installation

> [!IMPORTANT]
> Please perform the installation as the root user.

> Install via wget (jsDelivr CDN source)
```sh
export url='https://testingcf.jsdelivr.net/gh/juewuy/ShellCrash@dev' \
  && wget -q --no-check-certificate -O /tmp/install.sh $url/install_en.sh \
  && bash /tmp/install.sh \
  && . /etc/profile &> /dev/null
```

> Or install via curl (Author's private source)

```sh
export url='https://gh.jwsc.eu.org/dev' && bash -c "$(curl -kfsSl $url/install_en.sh)" && . /etc/profile &> /dev/null
```

### :satellite: Router Device Installation

**Installation via `curl`:**
> GitHub Source (Recommended for overseas environments or environments with proxy access)
```sh
export url='https://raw.githubusercontent.com/juewuy/ShellCrash/dev' \
  && sh -c "$(curl -kfsSl $url/install_en.sh)" \
  && . /etc/profile &> /dev/null
```

> Or jsDelivr CDN source

```sh
export url='https://testingcf.jsdelivr.net/gh/juewuy/ShellCrash@dev' \
  && sh -c "$(curl -kfsSl $url/install_en.sh)" \
  && . /etc/profile &> /dev/null
```

> Or Author's private source
```sh
export url='https://gh.jwsc.eu.org/dev' && sh -c "$(curl -kfsSl $url/install_en.sh)" && . /etc/profile &> /dev/null
```

**Installation via `wget`:**
> GitHub Source (Recommended for overseas environments or environments with proxy access)
```sh
export url='https://raw.githubusercontent.com/juewuy/ShellCrash/dev' \
  && wget -q --no-check-certificate -O /tmp/install.sh $url/install_en.sh \
  && sh /tmp/install.sh \
  && . /etc/profile &> /dev/null
```

> Or jsDelivr CDN source
```sh
export url='https://testingcf.jsdelivr.net/gh/juewuy/ShellCrash@dev' \
  && wget -q --no-check-certificate -O /tmp/install.sh $url/install_en.sh \
  && sh /tmp/install.sh \
  && . /etc/profile &> /dev/null
```

### :pager: Installation for Legacy Devices with Older `wget` Versions

> Author's private HTTP beta source
```sh
export url='http://t.jwsc.eu.org' \
  && wget -q -O /tmp/install.sh $url/install_en.sh \
  && sh /tmp/install.sh \
  && . /etc/profile &> /dev/null
```


### :cloud: Virtual Machines
- **Alpine Linux VM**: It is highly recommended to use an Alpine image for optimal compatibility.
```sh
# Install necessary dependencies
apk add --no-cache wget openrc ca-certificates tzdata nftables iproute2 dcron
# Execute installation command
export url='https://testingcf.jsdelivr.net/gh/juewuy/ShellCrash@dev' \
  && wget -q --no-check-certificate -O /tmp/install.sh $url/install_en.sh \
  && sh /tmp/install.sh \
  && . /etc/profile &> /dev/null
```

 ### :whale: Docker 

 Please visit the official Docker image:

- [ShellCrash on Docker Hub](https://hub.docker.com/r/juewuy/shellcrash)


### :package: Local Installation

If online installation is not possible, please follow the guide for local installation:

- [Local ShellCrash Installation Tutorial | Juewuy's Blog](https://juewuy.github.io/bdaz)

### macOS (Apple Silicon)

The installer downloads and verifies the macOS arm64 Mihomo release. Run `sh install_en.sh` from a checkout with the Darwin backend, or install online from `deploy`.

```sh
url='https://raw.githubusercontent.com/0x535a/ShellCrash-macOS/deploy'
installer=$(mktemp -t shellcrash)
curl -fsSL "$url/install_en.sh" -o "$installer" && env url="$url" sh "$installer"
```

For an online system installation, use `sudo env url="$url" sh "$installer"` in the last step. Pass an official `mihomo-*.gz` archive when installing from a checkout to use an offline core.

**User installation** uses `~/Library/Application Support/ShellCrash`. Open a new terminal to use the `crash` menu and Pure mode.

```sh
sh install_en.sh
crash -s start
crash -s status
crash -s autostart enable   # Start at login
crash -s stop
```

**System installation** uses `/Library/Application Support/ShellCrash`. Use `sudo` in the terminal to change the system service.

```sh
sudo sh install_en.sh
sudo /usr/local/bin/crash mode tun
sudo /usr/local/bin/crash -s start
crash --system -s status
sudo /usr/local/bin/crash -s autostart enable  # Start at boot
sudo /usr/local/bin/crash -s stop
```

Use `crash --user` or `crash --system` to select an instance. The user installation uses a `LaunchAgent` and the system installation uses a `LaunchDaemon`. Use the autostart menu or `crash -s autostart disable` to turn off future automatic starts. PF modes require a `pf_mount` helper compatible with the host's PF ABI in the system installation's `bin/` directory. Tproxy also requires `feth-qemu`. Run `crash -h` for configuration and mode commands.

---

## :book: Usage Instructions

After installation, enter the following commands in the terminal to launch the management interface:

```shell
crash        # Launch the interactive script menu
crash -h     # View the list of command help
```

### Linux Running Dependencies
| Component | Necessity | Description |
| :--- | :--- | :--- |
| curl / wget | Mandatory | Required for node saving, online installation, and update operations. |
| iptables / nftables | Critical | Without these, the script can only run in Pure Mode. |
| crontab | Low | Required for scheduled tasks; otherwise, they will not function. |
| net-tools | Very Low | Used for automatic port occupancy detection. |
| ubus / iproute-doc | Very Low | Used for automatically obtaining the local Host address. |

---

## :link: Related Links
- FAQ: [Juewuy's Blog](https://juewuy.github.io/chang-jian-wen-ti/)
- Changelog: [Release History](https://github.com/juewuy/ShellCrash/releases)
- Discussion: [Telegram Group](https://t.me/ShellClash)

## :scroll: License

This project is licensed under the [GNU General Public License v3.0](LICENSE.txt).
