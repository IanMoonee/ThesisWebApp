from django.contrib import admin
from django.urls import path
from django.conf.urls import url

# register_view
from pages.views import index_view, help_view, register
from lan_project.views import *

# TO NAME MPAINEI STHN HTML SELIDA sto method.POST.get('name')
urlpatterns = [
    # urls for ajax-calls.
    url(r'^enumeration/resultsArp', ajax_arp),
    url(r'^enumeration/resultsIcmp', ajax_icmp_ping),
    url(r'^enumeration/resultsSyn', ajax_syn),
    url(r'^enumeration/resultsGrab', ajax_banner_grabber),
    url(r'^enumeration/saveToDb', save_to_database),
    url(r'^enumeration/resultsCVEs', search_for_cves),
    path('', index_view, name='base'),
    path('base.html', index_view, name='base'),
    # path('NewWan/', OtherProject.as_view(), name='New_Wan'),
    path('ProjectSettings/', LanProject.as_view(), name='New_Lan'),
    path('help/', help_view, name='help'),
    path('sign-up/', register, name='register'),
    path('enumeration/', goto_enumeration_page),
    path('enumeration/resultsTable', populate_result_table, name='show-table'),
    path('enumeration/pieChart', render_result_pie, name='show-pie'),
    path('enumeration/traceroute', traceroute_view, name='traceroute'),
    path('admin/', admin.site.urls),
]