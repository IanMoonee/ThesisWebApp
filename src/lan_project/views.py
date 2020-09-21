import json
from ipaddress import IPv4Network
from django.http import HttpResponse, Http404, JsonResponse
from django.shortcuts import render, redirect
from django.views import View
from pylab import *
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from .forms import LanModelForm, ArpSpoofForm
from .models import UserProject
from lan_project.models import NvdData
from .utils import *


# LanProject Settings View
class LanProject(View):
    form_class = LanModelForm
    template_name = 'user_projects/LAN/LanSettings.html'

    def get(self, request):
        form = self.form_class
        # delete session variables(ports etc..) when LanSettings page is called
        session_keys = list(request.session.keys())
        for _key in session_keys:
            del request.session[_key]
        context = {
            'form': form
        }
        print('[+] GET METHOD for LanSettings.html called')
        return render(request, self.template_name, context)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            print('[+] POST METHOD for LanSettings.html called')
            _target = form.cleaned_data['subnet']
            project_name = form.cleaned_data['project_name']
            update_db = form.cleaned_data['update_db_option']
            # check if user specified specific ports to scan
            if form.cleaned_data['port_options'] == 'common':
                print('[+] Default port scan! Only common ports will be used!')
                ports = [21, 22, 23, 25, 53, 80, 443, 110, 139, 445, 143]
                for i in range(0, len(ports)):
                    ports[i] = int(ports[i])
                request.session['ports'] = ports
            else:
                print('[+] Wider scan selected(1-1024 ports). This will take some time.')
                # all available ports
                ports = list(range(1, 1024))
                request.session['ports'] = ports
            request.session['subnet'] = _target
            request.session['project_name'] = project_name
            if update_db:
                update_database()
                update_nvd_model()
            else:
                print('[+] Update Database option was not selected.')
            print('[+] POST METHOD completed. Redirecting to Dashboard.')
            # redirects to /dashboard page (urls.py redirect_dashboard function is being called)
            return redirect('/dashboard')
        return render(request, self.template_name, context={'form': form})


def arp_scan(request):
    if request.is_ajax():
        _target = request.session.get('subnet')
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=_target), timeout=3, verbose=0)
        arp_scan_results = []
        alive_hosts = []
        macs = []
        for sent, received in ans:
            arp_scan_results.append(
                {'IP': received[1].psrc, 'MAC': received[1].hwsrc, 'PORTS': '', 'SERVICES': '', 'CVE': '', 'DESCRIPTION': '', 'SERVICE_CVE': ''})
            alive_hosts.append(received[1].psrc)
            macs.append(received[1].hwsrc)
        print('ARP SCAN RESULTS:')
        for client in arp_scan_results:
            print('{}      {}'.format(client['IP'], client['MAC']))

        # only the alive hosts to use at port scan.
        request.session['alive_hosts'] = alive_hosts
        # request.session['arp_scan_results'] = arp_scan_results
        request.session['scan_results'] = arp_scan_results
        arp_data = {
            'ip_addresses': alive_hosts,
            'mac_addresses': macs,
            'message': 'Arp-Scanning completed'
        }
        return JsonResponse(arp_data, safe=False)
    else:
        raise Http404


def host_alive(request):
    if request.is_ajax():
        alive_hosts = []
        _target = request.session['subnet']
        # make a list of addresses out of target input(192.168.1.0/24)
        addresses = IPv4Network(_target)
        for host in addresses:
            if host in (addresses.network_address, addresses.broadcast_address):
                continue
            response = sr1(IP(dst=str(host)) / ICMP(), timeout=0.1, verbose=0)
            if response is None:
                print('Host {} is down or not responding'.format(host))
            elif int(response.getlayer(ICMP).type) == 3 and \
                    int(response.getlayer(ICMP).code) in [1, 2, 3, 9, 10, 13]:
                print('Host {} is blocking ICMP'.format(host))
            else:
                alive_hosts.append(str(host))
                print('HOST : {} is active'.format(host))
        request.session['alive_hosts'] = alive_hosts
        print('icmp-host alive completed.')
        # localhost message
        data = {'message': 'ICMP-scan completed'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    else:
        raise Http404


def syn_port_scan(request):
    if request.is_ajax():
        active_hosts = request.session.get('alive_hosts')
        scan_results = request.session.get('scan_results')
        ports = request.session.get('ports')
        for index, host in enumerate(active_hosts):
            for dst_port in ports:
                src_port = random.randint(1025, 65534)
                response = sr1(IP(dst=str(host)) / TCP(sport=src_port, dport=dst_port, flags='S'), timeout=1,
                               verbose=0)
                if response is None:
                    print('[+] Host: {} port {} is filtered'.format(host, dst_port))

                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        # send reset packet
                        sr(
                            IP(dst=str(host)) / TCP(sport=src_port, dport=dst_port, flags='R'),
                            timeout=1,
                            verbose=0,
                        )
                        print('Host {} has port {} open'.format(host, dst_port))
                        scan_results[index]['PORTS'] += str(dst_port) + ','
                    elif response.getlayer(TCP).flags == 0x14:
                        print('[-] Host {} has port {} closed!!'.format(host, dst_port))
                elif response.haslayer(ICMP):
                    if (
                            int(response.getlayer(ICMP).type) == 3 and
                            int(response.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
                    ):
                        print('[-] Host: {} port {} is filtered'.format(host, dst_port))
        print('[+] Syn-stealth scan completed')
        request.session['scan_results'] = scan_results
        syn_data = {
            'port_results': scan_results,
            'message': 'Port Scanning completed.'
        }
        return HttpResponse(json.dumps(syn_data), content_type='application/json')
    else:
        raise Http404


def banner_grabber_lan(request):
    if request.is_ajax():
        exception_list = []
        ports = request.session.get('ports')
        active_host_list = request.session.get('alive_hosts')
        scan_results = request.session.get('scan_results')
        for index, active_host in enumerate(active_host_list):
            for port in ports:
                try:
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    # set a connection timeout
                    socket_obj.settimeout(2)
                    con_result = socket_obj.connect_ex((active_host, port))
                    # if con_result equals 0 that means we established a connection
                    if port == 80 and con_result == 0:
                        # craft byte object to send to the server
                        bytes_to_send = str.encode("HEAD / HTTP/1.1\r\n\r\n")
                        socket_obj.send(bytes_to_send)
                        # decode server's answer
                        banner = socket_obj.recv(1024).decode('utf-8')
                        banner = reform_banner(banner)
                        banner = string_replacer(banner)
                        print('[+] {}:{} --> {}'.format(active_host, port, banner))
                        scan_results[index]['SERVICES'] += str(banner)
                        socket_obj.close()
                    # connection result for ports other than HTTP
                    if con_result == 0:
                        banner = socket_obj.recv(1024).decode('utf-8')
                        banner = string_replacer(banner)
                        banner = ServiceManager.analyze_service(banner)
                        print('[+] {}:{} --> {}'.format(active_host, port, banner))
                        scan_results[index]['SERVICES'] += str(banner) + ','
                        socket_obj.close()
                except Exception as ex:
                    exception_list += (str(ex))
                    print(ex)
        request.session['scan_results'] = scan_results
        print('[+] Banner grabber completed')
        banner_results = {
            'grabber_results': scan_results,
            'message': 'Banner Grabber completed'
        }
        return HttpResponse(json.dumps(banner_results), content_type='application/json')
    else:
        raise Http404


def cve_search(request):
    if request.is_ajax():
        scan_results_list = request.session.get('scan_results')
        for index, service in enumerate(scan_results_list):
            current_service = scan_results_list[index]['SERVICES']
            # current_service = '220 vsFTPd 3.0.3,Apache/2.4.41 Ubuntu'
            # find returns -1 if the value is not found
            if not current_service:
                print('[+] {}:Runs no services.No possible CVE'.format(scan_results_list[index]['IP']))
                scan_results_list[index]['CVE'] += ' '
                scan_results_list[index]['DESCRIPTION'] += ' '
            # Multiple services separated with ' , '
            elif current_service.find(',') != -1:
                print('[+] {} runs : {} '.format(scan_results_list[index]['IP'],
                                                 scan_results_list[index][
                                                     'SERVICES']))
                print('[+] Split different services')
                multiple_services = current_service.split(',')
                # multiple_services = ['220 vsFTPd 3.0.3', 'Apache/2.4.41 Ubuntu']
                #        index 0                   index 1
                # ['220 vsFTPd 3.0.3', 'Apache/2.4.41 Ubuntu']
                print(multiple_services)
                service_1 = ServiceManager.analyze_service(multiple_services[0])
                service_2 = ServiceManager.analyze_service(multiple_services[1])
                # service_1 = ['vsFTPd 3.0.3']
                # service_2 = ['Apache', '2.4.41']
                query_res_1, serv = ServiceManager.construct_query(service_1)
                query_res_2, serv_2 = ServiceManager.construct_query(service_2)
                # TODO: check if the list has more than one CVE.
                if isinstance(query_res_1, list):
                    # checking for empty queryset
                    if query_res_1:
                        cve_string = str(query_res_1[0]['cve'])
                        references_string = str(query_res_1[0]['references'])
                        reformed_refs = string_replacer(references_string)
                        scan_results_list[index]['CVE'] += str(cve_string)
                        scan_results_list[index]['DESCRIPTION'] += str(reformed_refs)
                        scan_results_list[index]['SERVICE_CVE'] += str(serv)
                else:
                    scan_results_list[index]['CVE'] += '--'
                    scan_results_list[index]['DESCRIPTION'] += '--'
                if isinstance(query_res_2, list):
                    if query_res_2:
                        cve_string = str(query_res_2[0]['cve'])
                        references_string = str(query_res_2[0]['references'])
                        reformed_refs = string_replacer(references_string)
                        scan_results_list[index]['CVE'] += str(cve_string)
                        scan_results_list[index]['DESCRIPTION'] += str(reformed_refs)
                        scan_results_list[index]['SERVICE_CVE'] += str(serv_2)
                else:
                    scan_results_list[index]['CVE'] += '--'
                    scan_results_list[index]['DESCRIPTION'] += '--'
            # One service only ( example: nginx or ZTE Mini Web Server 1.0)
            else:
                print('Query for one service only will be run.')
                print('[+] {} runs only {}'.format(scan_results_list[index]['IP'],
                                                   scan_results_list[index][
                                                       'SERVICES']))
                query = NvdData.objects.filter(description__contains=current_service).reverse()[:2].values('cve', 'references')
                q_list = list(query)
                if q_list:
                    cve_str = str(q_list[0]['cve'])
                    ref_str = str(q_list[0]['references'])
                    reformed_refs = string_replacer(ref_str)
                    scan_results_list[index]['CVE'] += str(cve_str)
                    scan_results_list[index]['DESCRIPTION'] += str(reformed_refs)
        request.session['final_list'] = scan_results_list
        print('Final scan list.', scan_results_list)
        cve_results = {
            'cve_results': scan_results_list,
            'message': 'Completed CVE search in local database'
        }
        return HttpResponse(json.dumps(cve_results), content_type='application/json')
    else:
        raise Http404


def update_database():
    subprocess.call("wget https://cve.mitre.org/data/downloads/allitems.csv.Z", shell=True)
    subprocess.call("uncompress allitems.csv.Z", shell=True)
    print('Database file downloaded and uncompressed..')


def redirect_dashboard(request):
    print('Redirect to dashboard function run!')
    context = {
    }
    return render(request, 'user_projects/LAN/dashboard.html', context)


def exploitation_page(request):
    if request.method == 'POST':
        form = ArpSpoofForm(request.POST)
        if form.is_valid():
            victim_ip = form.cleaned_data['victim_ip']
            host_ip = form.cleaned_data['host_ip']
            try:
                while True:
                    start_arp_spoof(victim_ip, host_ip)
                    start_arp_spoof(host_ip, victim_ip)
                    time.sleep(1)
            except KeyboardInterrupt:
                restore_arp_spoof(victim_ip, host_ip)
                restore_arp_spoof(host_ip, victim_ip)
            print(victim_ip)
            context = {
                'victim_ip': victim_ip,
                'host_ip': host_ip
            }
            return HttpResponse(json.dumps(context), content_type='application/json')
        else:
            form = ArpSpoofForm()
            scan_list = request.session.get('scan_results')
            subnet = request.session.get('subnet')
            # get the default gateway
            d_gateway = conf.route.route("0.0.0.0")[2]
            for index, ip in enumerate(scan_list):
                if scan_list[index]['IP'] == d_gateway:
                    scan_list[index]['IP'] += ' (d.gateway)'
            context = {
                'scan_list': scan_list,
                'subnet': subnet,
                'form': form
            }
            return render(request, 'user_projects/LAN/exploitation.html', context)
    else:
        # Get method(when the page renders for the first time)
        form = ArpSpoofForm()
        scan_list = request.session.get('scan_results')
        subnet = request.session.get('subnet')
        # get the default gateway
        d_gateway = conf.route.route("0.0.0.0")[2]
        for index, ip in enumerate(scan_list):
            if scan_list[index]['IP'] == d_gateway:
                scan_list[index]['IP'] += ' (d.gateway)'
        context = {
            'scan_list': scan_list,
            'subnet': subnet,
            'form': form
        }
        return render(request, 'user_projects/LAN/exploitation.html', context)


