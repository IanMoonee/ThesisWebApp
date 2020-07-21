from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import render, redirect
from django.views import View
from scapy.layers.dns import DNS, DNSQR
from .forms import WanModelForm
import whois
from scapy.all import *
from scapy.layers.inet import IP, UDP


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
            # TODO : check if IP is given in order to convert
            target = form.cleaned_data['domain_or_ip']
            project_name = form.cleaned_data['project_name']
            request.session['domain_or_ip'] = target
            print('Form is valid, redirecting....')
            return redirect('/WanDashboard')
        return render(request, self.template_name, context={'form': form})


# TODO: fix the JsonResp to HttpResp
def whois_lookup(request):
    if request.is_ajax():
        domain = request.session.get('domain_or_ip')
        res = whois.whois(domain)
        l_domain_name = res.domain_name
        l_whois_server = res.whois_server
        l_nameservers = res.name_servers
        l_emails = res.emails
        address = res.address
        city = res.city
        print(l_domain_name)
        # converting stuff
        nameservers = ' '.join([str(elem) for elem in l_nameservers])
        domain_name = ' '.join([str(elem) for elem in l_domain_name])
        # whois_server = ' '.join([str(elem) for elem in l_whois_server])
        emails = ' '.join([str(elem) for elem in l_emails])
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


def recursive_dns(request):
    if request.is_ajax():
        target = request.session.get('ip_or_domain')
        d_gateway = conf.route.route("0.0.0.0")[2]
        ans = sr1(IP(dst=d_gateway) / UDP(sport=RandShort()) / DNS(rd=1, qd=DNSQR(qname=target)))
        ans.summary()
        ans.show()
        return HttpResponse()
    else:
        return Http404


def redir_wan_dashboard(request):
    print('Redirecting to WanProject\'s dashboard')
    context = {
    }
    return render(request, 'user_projects/WAN/WanDashboard.html', context)
