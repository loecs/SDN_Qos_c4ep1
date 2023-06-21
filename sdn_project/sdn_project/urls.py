"""fuxi URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/2.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path,re_path
import fuxi.views as fuxi

urlpatterns = [
    # path('', fuxi.endpoint_list),
    # path('', fuxi.login,name='login'),
    path('', fuxi.index,name='index'),
    path('link-info/', fuxi.link_info,name='link-info'),
    path('modify_bandwidth/', fuxi.modify_bandwidth,name='modify_bandwidth'),
    path('endpoint-list/', fuxi.endpoint_list,name='endpoint-list'),
    path('unusual-traffic/', fuxi.unusual_traffic,name='unusual-traffic'),
    path('flow-table/', fuxi.flow_table,name='flow-table'),
    path('delete_flow_table/', fuxi.delete_flow_table,name='delete_flow_table'),
    path('add_flow_table/', fuxi.add_flow_table,name='add_flow_table'),
    path('meter-table/', fuxi.meter_table,name='meter-table'),
    path('delete_meter_table/', fuxi.delete_meter_table,name='delete_meter_table'),
    path('add_meter_table/', fuxi.add_meter_table,name='add_meter_table'),
    # path('admin/', admin.site.urls),
]
