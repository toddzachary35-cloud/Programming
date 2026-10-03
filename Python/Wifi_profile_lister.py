"""List saved Wi-Fi profiles and scan the currently connected Wi-Fi network."""

import ipaddress
import json
import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET


def run_command(command):
	"""Run a command and return its standard output."""
	result = subprocess.run(command, capture_output=True, text=True, check=False)
	if result.returncode != 0:
		message = result.stderr.strip() or "the command failed"
		raise RuntimeError(message)
	return result.stdout


def get_profiles():
	"""Get saved Wi-Fi profile names for the current operating system."""
	if platform.system() == "Windows":
		output = run_command(["netsh", "wlan", "show", "profiles"])
		return [
			line.split(":", 1)[1].strip()
			for line in output.splitlines()
			if "All User Profile" in line and ":" in line
		]

	if platform.system() == "Linux":
		output = run_command(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
		profiles = []
		for line in output.splitlines():
			name, connection_type = line.rsplit(":", 1)
			if connection_type == "802-11-wireless":
				profiles.append(name.replace("\\:", ":").replace("\\\\", "\\"))
		return profiles

	raise RuntimeError("This operating system is not supported.")


def get_wifi_network():
	"""Return the connected Wi-Fi interface and its local IPv4 subnet."""
	if platform.system() != "Linux":
		return None

	output = run_command(["nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device", "status"])
	interface = None
	for line in output.splitlines():
		device, device_type, state = line.rsplit(":", 2)
		if device_type == "wifi" and state == "connected":
			interface = device
			break
	if interface is None:
		return None

	addresses = json.loads(run_command(["ip", "-j", "-4", "addr", "show", "dev", interface]))
	for address in addresses[0].get("addr_info", []):
		if address.get("family") == "inet":
			ip_address = ipaddress.ip_interface(
				f"{address['local']}/{address['prefixlen']}"
			)
			return interface, ip_address.network
	return None


def scan_network(network):
	"""Use Nmap XML output to collect responsive hosts and OS guesses."""
	if shutil.which("nmap") is None:
		raise RuntimeError("nmap is not installed. Install it with: sudo apt install nmap")

	result = subprocess.run(
		["nmap", "-n", "-T3", "-O", "--osscan-limit", "-oX", "-", str(network)],
		capture_output=True,
		text=True,
		check=False,
	)
	if not result.stdout.strip():
		raise RuntimeError(result.stderr.strip() or "nmap returned no results")

	hosts = []
	root = ET.fromstring(result.stdout)
	for host in root.findall("host"):
		status = host.find("status")
		if status is None or status.get("state") != "up":
			continue
		addresses = {
			item.get("addrtype"): item.get("addr")
			for item in host.findall("address")
		}
		hostname = host.find("hostnames/hostname")
		os_match = host.find("os/osmatch")
		hosts.append({
			"ip": addresses.get("ipv4", "unknown"),
			"hostname": hostname.get("name") if hostname is not None else "-",
			"mac": addresses.get("mac", "-"),
			"vendor": next(
				(item.get("vendor", "") for item in host.findall("address") if item.get("addrtype") == "mac"),
				"-",
			),
			"os": os_match.get("name") if os_match is not None else "Unknown (try running with sudo)",
		})
	return hosts


def display_profiles(profiles):
	print("\nSaved Wi-Fi Profiles")
	print("=" * 21)
	if not profiles:
		print("No saved Wi-Fi profiles found.")
		return
	for index, profile in enumerate(profiles, start=1):
		print(f"{index:>2}. {profile}")
	print(f"\nTotal: {len(profiles)} profile(s)")


def display_hosts(interface, network, hosts):
	print(f"\nDevices on {interface} ({network})")
	print("=" * (24 + len(interface) + len(str(network))))
	if not hosts:
		print("No responsive devices found.")
		return
	print(f"{'IP address':<16} {'Hostname':<25} {'MAC address':<18} {'Vendor':<18} OS")
	print("-" * 105)
	for host in hosts:
		print(
			f"{host['ip']:<16} {host['hostname'][:24]:<25} "
			f"{host['mac']:<18} {host['vendor'][:17]:<18} {host['os']}"
		)
	print(f"\nResponsive devices: {len(hosts)}")


def main():
	try:
		display_profiles(get_profiles())
		wifi_network = get_wifi_network()
		if wifi_network is None:
			print("\nNo active Linux Wi-Fi connection found; device scan skipped.")
			return
		interface, network = wifi_network
		print("\nScanning the current local Wi-Fi network. This can take a moment...")
		display_hosts(interface, network, scan_network(network))
	except FileNotFoundError as error:
		print(f"Required command not found: {error.filename}")
	except (RuntimeError, ET.ParseError, json.JSONDecodeError) as error:
		print(f"Could not complete the Wi-Fi scan: {error}")


if __name__ == "__main__":
	main()
