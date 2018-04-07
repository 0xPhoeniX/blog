+++
title = "Portable Network Traffic Capture"
date = "2018-04-01T18:52:01-04:00"
slug = "portable-traffic-capture"
Tags = ["raspi", "ssl stripping", "wifi monitor", "IoT", "mobile"]
Categories = ["Tools"]
featuredImage = "images/monitoring.jpg"
+++

Recently,  I found myself in need of SSL traffic analysis coming out of IoT and mobile devices. After some considerations about the setup of monitoring gear I ended up with using Raspberry Pi 3 as a platform for that because most of the devices were with wifi only and I needed something more mobile at hand. There are some guides to set such platform up but I found them lacking certain things that prevented the whole thing from working for me. So, this article is mainly a notes for myself (and may be others) that got everything running smoothly at the end. I also ended up experimenting with Raspi being connected to the Internet through WiFi/Ethernet interfaces. So here I would describe both ways for convinience.

So, here are main solution objectives: 

- Minimal setup for monitored devices
- Wireless solution
- Portable

and components involved:

- Hardware
  - RasPi 3
  - WiFi dongle (optional)
- Software
  - Raspbian, November 2017 version
  - hostapd, dnsmasq, iptables, sslstrip, mitmproxy (optional)

## Network Interface Configuration

First things first - participating interfaces must be set up. There are several options for that where WiFi hotspot interface (`wlan0`) is common for devices to connect to and following options for Internet gateway:

- Ethernet interface `eth0` - RasPI has one free port available
- Additional WiFi interface `wlan1`  - additional doungle must be [purchased](https://www.buyapi.ca/product/miniature-wifi-adapter-official-raspberry-pi-edition/). This would provide a complete wireless monitoring solutions :-)

In both cases  `/etc/network/interfaces` should be edited accordingly. In case of Internet gateway interface, it's address would be assigned by ISP DHCP server, while WIFi hotspot address must be set manually as this information would be needed during the `hostapd` setup.

#### WiFi Hotspot + Ethernet Internet interface

```
auto eth0
allow-hotplug eth0
iface eth0 inet dhcp

allow-hotplug wlan0
iface wlan0 inet static
	address   192.168.10.1
	netmask   255.255.255.0
	network   192.168.10.0
	broadcast 192.168.10.255
```

Note: If you like me had problem with `eth0` interface being renamed to something else, try to fix this by adding `net.ifnames=0` to `/boot/cmdline.txt`. This what helped me to fix it.

#### WiFi Hotspot + WiFi Internet interface

```
auto wlan1
iface wlan1 inet dhcp
	wpa-ssid YOUR-SSID-HERE
	wpa-psk YOUR-PASSWORD-HERE

allow-hotplug wlan0
iface wlan0 inet static
    address   192.168.10.1
    netmask   255.255.255.0
    network   192.168.10.0
    broadcast 192.168.10.255
```

It should be noted that `wpa_supplicant` must be installed beforehead.

#### Local DHCP client

To privent collision, WiFi hotspot interface must be excluded from local DHCP client configuration (`/etc/dhcpcd.conf`) by adding one line at the bottom:

	denyinterfaces wlan0
And restart the interfaces:

```bash
sudo /etc/init.d/networking restart
```

## Setting up Access Point

`hostapd` will be used as AP daemon. So let's install it and prepare configuration file:

```bash
sudo apt-get install hostapd
cd /etc/hostapd/
sudo cp /usr/share/doc/hostapd/examples/hostapd.conf.gz .
sudo gunzip ./hostapd.conf.gz
```
Now there are some parameters that must be changed in `/etc/hostapd/hostapd.conf`
```
interface=wlan0					# AP interface name
driver=nl80211
ssid=AP-SSID-HERE				# The name of your new AP
hw_mode=g
channel=11					# WiFi transmission channel
ieee80211n=1
wmm_enabled=1
ht_capab=[HT40][SHORT-GI-20][DSSS_CCK-40]
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_passphrase=PASSWORD-HERE			# The password for AP access
rsn_pairwise=CCMP
```

Next, let's check that the new AP is accessable by starting  `hostapd` manually:

```bash
sudo /usr/sbin/hostapd /etc/hostapd/hostapd.conf
```

You should see the AP by the name that was given in the config file and be able to connect to it with the preconfigured password. Upon success, `hostapd` should be configured as a service by editing `DAEMON_CONF` variable in `/etc/default/hostapd`:

```
DAEMON_CONF="/etc/hostapd/hostapd.conf"
```

Now, let's enable `hostapd` service, start it and check the status:

```bash
sudo systemctl enable hostapd.service
sudo systemctl restart hostapd.service
sudo systemctl status hostapd.service
```

## Setting up DNS Server

This setup is using `dnsmasq` for its DNS server needs. So let's edit `/etc/dnsmasq.conf`:

```
interface=wlan0					# AP interface
bind-interfaces
server=8.8.8.8					# ISP DNS  server
domain-needed  
bogus-priv
listen-address=192.168.10.1			# The IP of AP interface

# The range must be different from your AP interface network
dhcp-range=192.168.13.10,192.168.13.240,12h
```

Restart the service and check its status:

```bash
sudo systemctl restart dnsmasq
sudo systemctl status dnsmasq
```

## IpTables and Internel access

Let's continue to  enable Internet access for all AP clients. Enable IP forwarding:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```
and make it persist after reboot by edititng `/etc/sysctl.conf`:
```
net.ipv4.ip_forward = 1
```
Lastly `iptables` should take care of traffic routing between AP interface and Internet interface.

For _Ethernet option_:
```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -A FORWARD -i eth0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o eth0 -j ACCEPT
```
or for _WiFi_ option:
```bash
sudo iptables -t nat -A POSTROUTING -o wlan1 -j MASQUERADE
sudo iptables -A FORWARD -i wlan1 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o wlan1 -j ACCEPT
```

Save the table rules into a file for persistance:
```bash
sudo sh -c "iptables-save > /etc/iptables.rules"
```
And load the rules back again after reboot through adding line in  `/etc/network/interfaces`:
```
up iptables-restore < /etc/iptables.rules
```

At this point all AP clients should be able to access Internet without any issues. If you have one, please leave a comment so we can try and resolve it.

## Traffic Monitoring preps

I'd like to add several examples of useful tools that should be used with the above setup. Please, take into account that `mitmproxy` setup regarding traffic redirection doubles the one for `SSLsplit`. So if you set up `SSLsplit` forwarding params, you should not be doit anything for `mitmproxy`. Just reuse the same setup for both tools.

### Preparations for SSLsplit

We will not discuss how to actually use [SSLsplit](https://www.roe.ch/SSLsplit) here as there are some good resources already available for that. Instead, let's prepare the environment for its usage. 

Install the SSLsplit:

```bash
sudo apt install sslsplit
```

SSLsplit needs CA certificate pair to be generated and `ca.crt` must be [imported](https://support.google.com/nexus/answer/2844832?hl=en) into target device root CA certificate trust store:

```bash
mkdir -p ssl_monitoring/logdir ssl_monitoring/jaildir
cd ssl_monitoring
openssl genrsa -out ca.key 4096
openssl req -new -x509 -days 1826 -key ca.key -out ca.crt
```
In addition, network traffic must be forwarded to SSLsplit controlled ports for further processing. This setup is needed only once to prepare the `iptable` rules - restore to the clean table and add `sslsplit` specifics:

```bash
sudo iptables-restore < /etc/iptables.rules
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 587 -j REDIRECT --to-ports 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 465 -j REDIRECT --to-ports 8443
sudo iptables -t nat -A PREROUTING -p tcp --dport 993 -j REDIRECT --to-ports 8443
sudo sh -c "iptables-save > ssl_monitoring/iptables.sslsplit"
```
and the next time, when the `sslsplit` is used, just load the rules before starting to do anything:
```
sudo iptables-restore < ssl_monitoring/iptables.sslsplit
```
In the above example HTTPS, IMAP (over SSL) and SMTP (over SSL) are forwarded to `8443` port which is monitored by SSLsplit. In case other ports are needed, they can be added to the `iptables` in the similar way.

And start SSLsplit for capturing:

```bash
sudo sslsplit 
  -l conn.log 
  -j jaildir/ 
  -S logdir/ 
  -k ca.key 
  -c ca.crt 
   ssl 0.0.0.0 8443 
   tcp 0.0.0.0 8080
```

More information about how to use SSLsplit could be found on its author's [site](https://www.roe.ch/SSLsplit).

### Preparations for MitmProxy

Install mitmproxy by:

```bash
sudo pip3 install mitmproxy
```

and traffic forwarding will be taken care of by `iptables`.  This setup needs to done only once:

```bash
sudo iptables-restore < /etc/iptables.rules
sudo iptables -t nat -F
sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports 8080
sudo sh -c "iptables-save > ssl_monitoring/iptables.mitmproxy"
```
The final thing is to register mitmproxy as a trusted CA with the target device. ([Android](https://support.google.com/nexus/answer/2844832?hl=en))

From now on, load only the  mitmproxy rules and we are done:
```
sudo iptables-restore < ssl_monitoring/iptables.mitmproxy
```
Now, let's get some traffic:

```bash
sudo mitmproxy --mode transparent
```
If you want to re-use the certs that were generated previously, there is one another thing left to do - generate PEM format of certificate:
```
cat ca.key ca.crt \> ca.pem
sudo mitmproxy --mode transparent --certs *=ca.pem
```

That's all folks!