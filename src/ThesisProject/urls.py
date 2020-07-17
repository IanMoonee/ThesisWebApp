from django.contrib import admin
from django.urls import path, re_path
from django.conf.urls import url

# register_view
from pages.views import index_view, help_view
from lan_project.views import *
from wan_project.views import *

# TO NAME MPAINEI STHN HTML SELIDA sto method.POST.get('name')
urlpatterns = [
    # urls for ajax-calls.
    re_path('^dashboard/resultsArp', ajax_arp),
    re_path('^dashboard/resultsIcmp', ajax_icmp_ping),
    re_path('^dashboard/resultsSyn', ajax_syn),
    re_path('^dashboard/resultsGrab', ajax_banner_grabber),
    re_path('^dashboard/saveToDb', save_to_database),
    re_path('^dashboard/resultsCVEs', search_for_cves),
    path('', index_view, name='base'),
    path('base', index_view, name='base'),
    path('WanSettings/', WanProject.as_view(), name='New_Wan'),
    path('LanSettings/', LanProject.as_view(), name='New_Lan'),
    path('help/', help_view, name='help'),
    path('dashboard/', redirect_dashboard),
    path('WanDashboard/', redir_wan_dashboard),
    path('dashboard/resultsTable', populate_result_table, name='show-table'),
    path('dashboard/pieChart', render_result_pie, name='show-pie'),
    path('dashboard/traceroute', traceroute_view, name='traceroute'),
    path('admin/', admin.site.urls),
]
