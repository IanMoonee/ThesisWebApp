from django.contrib import admin
from django.urls import path, re_path

from pages.views import index_view, help_view
from lan_project.views import *
from wan_project.views import *

# TO NAME MPAINEI STHN HTML SELIDA sto method.POST.get('name')
urlpatterns = [
    # urls for ajax-calls.
    re_path('^dashboard/resultsArp', arp_scan),
    re_path('^dashboard/resultsIcmp', host_alive),
    re_path('^dashboard/resultsSyn', syn_port_scan),
    re_path('^dashboard/resultsGrab', banner_grabber_lan),
    re_path('^dashboard/resultsCVEs', cve_search),
    # re_path('^dashboard/Exploitation/ArpSpoof', arp_spoof),
    re_path('^WanDashboard/whoisLookup', whois_lookup),
    re_path('^WanDashboard/recursiveDns', recursive_dns),
    re_path('^WanDashboard/portScanner', syn_port_scanner),
    re_path('^WanDashboard/bannerGrabber', banner_grabber),
    re_path('^WanDashboard/subDomains', subdomain_enumeration),
    re_path('^WanDashboard/directoryFuzzing', directory_fuzzer),
    path('', index_view, name='base'),
    path('base', index_view, name='base'),
    path('WanSettings/', WanProject.as_view(), name='New_Wan'),
    path('LanSettings/', LanProject.as_view(), name='New_Lan'),
    # path('dashboard/Exploitation', arp_spoof_ip, name='Arp_Spoof'),
    # path('dashboard/Exploitation/ArpPoison', arp_spoof_ip, name='Arp_Spoof'),
    path('help/', help_view, name='help'),
    path('dashboard/', redirect_dashboard),
    path('WanDashboard/', redir_wan_dashboard),
    path('dashboard/Exploitation', exploitation_page, name='Lan-attacks'),
    path('WanDashboard/traceroute', traceroute_view, name='traceroute'),
    path('admin/', admin.site.urls),
]
