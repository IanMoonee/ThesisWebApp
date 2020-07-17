import json
from ipaddress import IPv4Network
import PIL
import PIL.Image
from django.http import HttpResponse, Http404
from django.shortcuts import render, redirect
# import for the class-based-views
from django.views import View
from matplotlib import pylab as plt
from pylab import *
from scapy.all import *
from scapy.layers.inet import TCP, IP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.inet import traceroute as trc
from .forms import LanModelForm
from .models import UserProject
from lan_project.models import NvdData
from .utils import *


# Class based view for wide-area network scans.

# New Lan Project starting page.
class LanProject(View):
    form_class = LanModelForm
    template_name = 'user_projects/LAN/LanSettings.html'

    def get(self, request):
        form = self.form_class
        # delete session variables(ports etc..) when newProject page
        # is loaded
        session_keys = list(request.session.keys())
        for kappa in session_keys:
            del request.session[kappa]
        context = {
            'form': form
        }
        print('New Lan project get method accessed.')
        return render(request, self.template_name, context)

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            print('NewLan post method accessed.')
            _target = form.cleaned_data['subnet']
            project_name = form.cleaned_data['project_name']
            update_or_not = form.cleaned_data['update_db_option']
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
            if update_or_not:
                update_nvd_database()
                update_nvd_model()
            else:
                print('Update database option was not selected.')
            print('Redirect to dashboard page after POST.')
            # redirects to /dashboard page (urls.py redirect_dashboard function is being called)
            return redirect('/dashboard')
        return render(request, self.template_name, context={'form': form})


def ajax_arp(request):
    if request.is_ajax():
        _target = request.session.get('subnet')
        ans, _ = srp(Ether(dst='ff:ff:ff:ff:ff:ff') / ARP(pdst=_target), timeout=3, verbose=0)
        arp_scan_results = []
        alive_hosts = []
        macs = []
        for sent, received in ans:
            arp_scan_results.append(
                {'IP': received[1].psrc, 'MAC': received[1].hwsrc, 'PORTS': '', 'SERVICES': '', 'CVE': ''})
            alive_hosts.append(received[1].psrc)
            macs.append(received[1].hwsrc)
        print('ARP SCAN RESULTS:')
        for client in arp_scan_results:
            print('{}      {}'.format(client['IP'], client['MAC']))

        # only the alive hosts to use at port scan.
        request.session['alive_hosts'] = alive_hosts
        request.session['macs'] = macs
        request.session['arp_scan_results'] = arp_scan_results
        request.session['scan_results'] = arp_scan_results
        data = {'message': 'Arp-scan completed, Continue with stealth port scanning'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    else:
        raise Http404


def ajax_icmp_ping(request):
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


def ajax_syn(request):
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
                    print('Host: {} port {} is filtered'.format(host, dst_port))

                elif response.haslayer(TCP):
                    if response.getlayer(TCP).flags == 0x12:
                        # send reset packet
                        sr(
                            IP(dst=str(host)) / TCP(sport=src_port, dport=dst_port, flags='R'),
                            timeout=1,
                            verbose=0,
                        )
                        print('Host {} has port {} open'.format(host, dst_port))
                        # TODO: line below is not needed.
                        # populate PORTS in the arp_results
                        scan_results[index]['PORTS'] += str(dst_port) + ','
                        # hosts_with_ports.append({'Host': host, 'Port': dst_port})
                    elif response.getlayer(TCP).flags == 0x14:
                        print('Host {} has port {} closed!!'.format(host, dst_port))
                elif response.haslayer(ICMP):
                    if (
                            int(response.getlayer(ICMP).type) == 3 and
                            int(response.getlayer(ICMP).code) in (1, 2, 3, 9, 10, 13)
                    ):
                        print('Host: {} port {} is filtered'.format(host, dst_port))
        print('[+] Syn-stealth scan completed')
        request.session['scan_results'] = scan_results
        # localhost message after ajax request is completed
        data = {'message': 'Scan completed.Proceed with grabbing running services.'}
        return HttpResponse(json.dumps(data), content_type='application/json')
    else:
        raise Http404


def ajax_banner_grabber(request):
    if request.is_ajax():
        exception_list = []
        ports = request.session.get('ports')
        active_host_list = request.session.get('alive_hosts')
        scan_results = request.session.get('scan_results')
        for index, active_host in enumerate(active_host_list):
            for port in ports:
                try:
                    socket_obj = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    socket_obj.settimeout(2)
                    con_result = socket_obj.connect_ex((active_host, port))
                    if port == 80 and con_result == 0:
                        bytes_to_send = str.encode("HEAD / HTTP/1.1\r\n\r\n")
                        socket_obj.send(bytes_to_send)
                        banner = socket_obj.recv(1024).decode('utf-8')
                        banner = reform_banner(banner)
                        banner = string_replacer(banner)
                        print('[+] {}:{} --> {}'.format(active_host, port, banner))
                        scan_results[index]['SERVICES'] += str(banner)
                        socket_obj.close()
                    if con_result == 0:
                        banner = socket_obj.recv(1024).decode('utf-8')
                        banner = string_replacer(banner)
                        print('[+] {}:{} -->{}'.format(active_host, port, banner))
                        scan_results[index]['SERVICES'] += str(banner) + ','
                        socket_obj.close()
                except Exception as ex:
                    exception_list += (str(ex))
        request.session['scan_results'] = scan_results
        print('[+] Banner grabbing completed')
        message = {'message': 'Banner grabbing for all hosts is complete'}
        return HttpResponse(json.dumps(message), content_type='application/json')
    else:
        raise Http404


# def search_for_cves(request):
#     if request.is_ajax():
#         scan_results_list = request.session.get('scan_results')
#         with connection.cursor() as cursor:
#             for final_list_index, service in enumerate(scan_results_list):
#                 current_service = scan_results_list[final_list_index]['SERVICES']
#                 # find returns -1 if the value is not found
#                 if not current_service:
#                     print('[+] Host {} has no active services'.format(scan_results_list[final_list_index]['IP']))
#                 elif current_service.find(',') != -1:
#                     print('Host {} has multiple services running : {}'.format(scan_results_list[final_list_index]['IP'],
#                                                                               scan_results_list[final_list_index][
#                                                                                   'SERVICES']))
#                     print('Spitting the different services for host {} in a new list.'.format(
#                         scan_results_list[final_list_index]['IP']))
#                     multiple_services = current_service.split(',')
#                     #   index 0        index 1
#                     # ['Apache/2.4.41', 'vsFTPd 3.0.3']
#                     # If host has multiple services running separated with ','
#                     # we are looping through each one
#                     for i, spl_service in enumerate(multiple_services):
#                         # second service vsFTPd does not have str1 and str2 being returned
#                         analyzed_result, str1, str2 = ServiceManager.analyze_service(spl_service)
#                         if analyzed_result and str1 and str2:
#                             cursor.execute("SELECT CVE FROM 'Nvd-data' where DESCRIPTION like %s and field1 like %s", [str1, str2])
#                             returned_list = cursor.fetchall()
#                             if returned_list:
#                                 print('SQL query ran for {}'.format(spl_service))
#                                 returned_list[0] = list_refactor_services(returned_list[0])
#                                 returned_list[1] = list_refactor_services(returned_list[1])
#                                 table_list = returned_list[0] + returned_list[1]
#                                 scan_results_list[final_list_index]['CVE'] += str(table_list)
#                                 print('Service {} parsed correctly'.format(spl_service))
#                         else:
#                             cursor.execute("SELECT CVE FROM 'Nvd-data' where DESCRIPTION like %s", [analyzed_result])
#                 # case there is only one service for X host.
#                 else:
#                     returned_service, str1, str2 = ServiceManager.analyze_service(current_service)
#                     print(returned_service)
#                     print(current_service)
#                     if returned_service and str1 and str2:
#                         cursor.execute("SELECT CVE FROM 'Nvd-data' where DESCRIPTION like %s and field1 like %s",
#                                        [str1, str2])
#                         res = cursor.fetchall()
#                         print('RESULT FROM DATABASE ', res)
#                         if res:
#                             res[0] = list_refactor_services(res[0])
#                             res[1] = list_refactor_services(res[1])
#                             table_list = res[0] + res[1]
#                             scan_results_list[final_list_index]['CVE'] += str(table_list)
#         print('Results after CVEs were added')
#         request.session['final_list'] = scan_results_list
#         print(scan_results_list)
#         message = {'message': 'Search completed in local database for public vulnerabilities.'}
#         return HttpResponse(json.dumps(message), content_type='application/json')
#     else:
#         raise Http404

def search_for_cves(request):
    if request.is_ajax():
        scan_results_list = request.session.get('scan_results')
        print('testing database API..')
        # _testing = 'apache'
        # result_db = NvdData.objects.filter(description__contains=str(_testing))
        # print(result_db)
        for index, service in enumerate(scan_results_list):
            current_service = scan_results_list[index]['SERVICES']
            # find returns -1 if the value is not found
            if not current_service:
                print('[+] {}:Runs no services.No possible CVE'.format(scan_results_list[index]['IP']))
            elif current_service.find(',') != -1:
                print('[+] {} runs : {} '.format(scan_results_list[index]['IP'],
                                                 scan_results_list[index][
                                                     'SERVICES']))
                print('[+] Split different services to construct the URL\'s')
                multiple_services = current_service.split(',')
                #   index 0          index 1
                # ['Apache/2.4.41', 'vsFTPd 3.0.3']
                # logic for multiple services
                print(multiple_services[0])
            else:
                print('[+] {} runs only {}'.format(scan_results_list[index]['IP'],
                                                   scan_results_list[index][
                                                       'SERVICES']))
        request.session['final_list'] = scan_results_list
        print('Final scan list.', scan_results_list)
        message = {'message': 'Cve search completed'}
        return HttpResponse(json.dumps(message), content_type='application/json')
    else:
        raise Http404


def traceroute_view(request):
    # submit button name .get
    if request.POST.get('traceroute'):
        # get textBox value by its name
        host_addr = request.POST.get('host_addr')
        print(host_addr)
        ans, unans = trc(host_addr)
        ans.graph(target="> static/images/trc.svg")
        return render(request, 'user_projects/LAN/graphs.html', context={})


def populate_result_table(request):
    if request.POST.get('Show-table'):
        subnet = request.session.get('subnet')
        final_list = request.session.get('final_list')
        table_context = {
            'subnet': subnet,
            'final_list': final_list,
        }
        return render(request, 'user_projects/LAN/dashboard.html', table_context)


# PieChart of open ports per host or CVE's perhost.
def render_result_pie(request):
    if request.POST.get('Show-pie'):
        labels = ['Port:80(http)', 'Port:21(ftp)', 'Port:443(https)']
        sizes = [1, 2, 0]
        colors = ['#ff9999', '#66b3ff', '#99ff99']
        # distances between stuff
        explode = (0.05, 0.05, 0.05)
        plt.title('Open ports')
        fig1, ax1 = plt.subplots()
        ax1.pie(sizes, labels=labels, colors=colors, shadow=True, autopct='%1.1f%%', pctdistance=0.85, startangle=90,
                explode=explode)
        # draw circle
        centre_circle = plt.Circle((0, 0), 0.70, fc='white')
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)
        # Ensure that is a circle
        ax1.axis('equal')
        plt.tight_layout()
        canvas = plt.get_current_fig_manager().canvas
        canvas.draw()
        pil_image = PIL.Image.frombytes('RGB', canvas.get_width_height(), canvas.tostring_rgb())
        pil_image.save('static/images/result_graph.png')
        return render(request, 'user_projects/LAN/graphs.html', context={})


# SQLITE3 database recognizes the file as json!
def save_to_database(request):
    if request.is_ajax():
        # starting dict with project's info
        info_dict = {
            'Project_name': request.session.get('project_name'),
            'subnet': request.session.get('subnet')
        }
        usr_instance = UserProject()
        scanning_results_list = request.session.get('arp_results')
        # dictionary with scanning results.
        scanning_res_dictionary = {}
        for item in scanning_results_list:
            ip = item['IP']
            scanning_res_dictionary[ip] = item
        print(scanning_res_dictionary)
        usr_instance.project_name = request.session.get('project_name')
        usr_instance.subnet = request.session.get('subnet')
        # add project's info to results dict and create a final dict
        final_dict = {**info_dict, **scanning_res_dictionary}
        # save it to the database at lan_project_userproject table
        usr_instance.json_data = json.dumps(final_dict).encode('utf-8')
        usr_instance.save()
        return HttpResponse()


def redirect_dashboard(request):
    print('Redirect to dashboard function run!')
    context = {
    }
    return render(request, 'user_projects/LAN/dashboard.html', context)


def update_nvd_database():
    subprocess.call("wget https://cve.mitre.org/data/downloads/allitems.csv.Z", shell=True)
    subprocess.call("uncompress allitems.csv.Z", shell=True)
    print('Database file downloaded and uncompressed..')
