# Django imports
from django.http import Http404, JsonResponse
from django.shortcuts import render, redirect
from django.views import View
from .forms import WanModelForm
from lan_project.utils import *
# basic python import modules
import random
import whois
import socket
import requests
import time

# scapy imports
from scapy.layers.inet import IP, UDP, ICMP, TCP
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sr1, sr
from scapy.volatile import RandShort
from scapy.config import conf
from scapy.layers.inet import traceroute
# from scapy.utils import whois as scapy_whois


class WanProject(View):
    form_class = WanModelForm
    template_name = 'user_projects/WAN/WANSettings.html'

    def get(self, request):
        form = self.form_class
        context = {
            'form': form
        }
        print('WanProject GET method accessed.')
        return render(request, self.template_name, context)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            print('POST method accessed')
            target = form.cleaned_data['domain_or_ip']
            request.session['domain_or_ip'] = target
            project_name = form.cleaned_data['project_name']
            if form.cleaned_data['port_options'] == 'common':
                print('[+] Default port scan!')
                ports = [21, 22, 23, 25, 53, 80, 443, 110, 139, 445, 143]
                for i in range(0, len(ports)):
                    ports[i] = int(ports[i])
                request.session['ports'] = ports
            else:
                print('[+] Wider scan selected(1-1024 ports)..')
                ports = list(range(1, 1024))
                request.session['ports'] = ports
            print('Form is valid, redirecting....')
            return redirect('/WanDashboard')
        return render(request, self.template_name, context={'form': form})


def whois_lookup(request):
    if request.is_ajax():
        domain = request.session.get('domain_or_ip')
        res = whois.whois(domain)
        if res.domain_name is None:
            domain_name = 'Empty'
            nameservers = 'Empty'
            emails = 'Empty'
            address = 'Empty'
            city = 'Empty'
            whois_server = 'Empty'
            whois_data = {
                'domain_list': domain_name,
                'whois_server': whois_server,
                'nameservers': nameservers,
                'emails': emails,
                'address': address,
                'city': city
            }
            return JsonResponse(whois_data, safe=False)
        else:
            l_domain_name = res.domain_name
            l_whois_server = res.whois_server
            l_nameservers = res.name_servers
            l_emails = res.emails
            address = res.address
            city = res.city
            nameservers = ' '.join([str(elem) for elem in l_nameservers])
            domain_name = ' '.join([str(elem) for elem in l_domain_name])
            emails = l_emails
            whois_data = {
                'domain_list': domain_name,
                'whois_server': l_whois_server,
                'nameservers': nameservers,
                'emails': emails,
                'address': address,
                'city': city
            }
            return JsonResponse(whois_data, safe=False)
    else:
        raise Http404


# TODO : set the target onDashboard for recursive DNS query
#        Not all DNS servers are open!!
#        ::Example:: openDNSservers -->  (Cloudflare, Google open DNS, OpenDNS)
#        OpenDns servers can be DoSed with Amplification Attacks
#
def recursive_dns(request):
    if request.is_ajax():
        target = request.session.get('domain_or_ip')
        d_gateway = conf.route.route("0.0.0.0")[2]
        ans = sr1(IP(dst=d_gateway) / UDP(sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=target)))
        results = ans.show()
        print(type(results))
        return JsonResponse(results, safe=False)
    else:
        return Http404


def redir_wan_dashboard(request):
    print('Redirecting to WanProject\'s dashboard')
    context = {
    }
    return render(request, 'user_projects/WAN/WanDashboard.html', context)


def syn_port_scanner(request):
    if request.is_ajax():
        target = request.session.get('domain_or_ip')
        ports = request.session.get('ports')
        open_ports = []
        src_port = random.randint(1025, 65534)
        for dst_port in ports:
            response = sr1(IP(dst=str(target)) / TCP(sport=src_port, dport=dst_port, flags='S'), timeout=1,
                           verbose=0)
            if response is None:
                print('Host: {} port {} is filtered'.format(target, dst_port))
            elif response.haslayer(TCP):
                if response.getlayer(TCP).flags == 0x12:
                    # send reset packet
                    sr(
                        IP(dst=str(target)) / TCP(sport=src_port, dport=dst_port, flags='R'),
                        timeout=1,
                        verbose=0,
                    )
                    print('Host {} has port {} open'.format(target, dst_port))
                    open_ports.append(dst_port)
                elif response.getlayer(TCP).flags == 0x14:
                    print('Host {} has port {} closed!!'.format(target, dst_port))
            elif response.haslayer(ICMP):
                if (
                        int(response.getlayer(ICMP).type) == 3 and
                        int(response.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
                ):
                    print('Host: {} port {} is filtered'.format(target, dst_port))
        print('[+] Syn-stealth scan completed')
        request.session['ports'] = open_ports
        # localhost message after ajax request is completed
        results = {
            'message': 'Port Scanning Completed.',
            'open_ports': open_ports
        }
        return JsonResponse(results, safe=False)
    else:
        return Http404


def banner_grabber(request):
    if request.is_ajax():
        services = []
        exception_list = []
        ports = request.session.get('ports')
        target_host = request.session.get('domain_or_ip')
        for port in ports:
            try:
                socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                socket_obj.settimeout(2)
                con_result = socket_obj.connect_ex((target_host, port))
                if port == 80 and con_result == 0:
                    # forge an HTTP request to SEND to the server
                    bytes_to_send = str.encode("HEAD / HTTP/1.1\r\n\r\n")
                    socket_obj.send(bytes_to_send)
                    banner = socket_obj.recv(1024).decode('utf-8')
                    print('[+] {}:{} --> {}'.format(target_host, port, banner))
                    for service in banner.split('\n'):
                        if 'Server:' in service:
                            banner = service[8:]
                    services.append(banner)
                    socket_obj.close()
                if con_result == 0:
                    banner = socket_obj.recv(1024).decode('utf-8')
                    print('[+] {}:{} --> {}'.format(target_host, port, banner))
                    services.append(banner)
                    socket_obj.close()
            except Exception as ex:
                exception_list += (str(ex))
            results = {
                'message': 'Banner Grabber Completed.',
                'services': services
            }
            print('[+] Banner grabbing completed')
            return JsonResponse(results, safe=False)
    else:
        raise Http404


def subdomain_enumeration(request):
    if request.is_ajax():
        subdomain_list = []
        target = request.session.get('domain_or_ip')
        with open('subdomains.txt') as file:
            contents = file.read()
            subdomains = contents.splitlines()
            for subdomain in subdomains:
                url = f'https://{subdomain}.{target}'
                try:
                    requests.get(url)
                    print(url)
                except requests.ConnectionError:
                    pass
                else:
                    print('[+] SUBDOMAIN FOUND : ', url)
                    print(url)
                    subdomain_list.append(url)
                    subdomain_list.append('<br>')
            response_data = {
                'subdomains_found': subdomain_list
            }
        return JsonResponse(response_data, safe=False)
    else:
        return Http404


def directory_fuzzer(request):
    if request.is_ajax:
        directory_list = []
        sensitive_files = []
        domain_given = request.session.get('domain_or_ip')
        if domain_given.startswith('https://') or domain_given.startswith('http://'):
            print('Domain is okay :', domain_given)
            domain_given = domain_given + '/'
        else:
            domain_given = 'https://' + domain_given + '/'
            print('Domain reformed : ', domain_given)
        with open('dirs.txt') as file:
            contents = file.read()
            directories = contents.splitlines()
            for directory in directories:
                url = domain_given + directory
                print(url)
                time.sleep(0.01)
                response = requests.get(url)
                if response.status_code == 200:
                    print('[+] FOUND : ', url)
                    directory_list.append(url)
                    directory_list.append('<br>')
                else:
                    print('[-] Directory does not exist :', url)
            if 'robots.txt' in directory_list:
                sensitive_files.append('robots.txt')
            print(directory_list)
            print(sensitive_files)
            response_data = {
                'directories': directory_list,
                'sensitive_files': sensitive_files
            }
        return JsonResponse(response_data, safe=False)
    else:
        return Http404


def traceroute_view(request):
    # submit button name .get
    if request.POST.get('traceroute'):
        domain_address = request.session.get('domain_or_ip')
        print('Running scapy traceroute on : ', domain_address)
        ans, unans = traceroute(domain_address)
        ans.graph(target="> static/images/trc.svg")
        return render(request, 'user_projects/WAN/graphs.html', context={})
