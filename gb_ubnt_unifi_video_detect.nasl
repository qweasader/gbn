###############################################################################
# OpenVAS Vulnerability Test
#
# Ubiquiti Networks Unifi Video Detection
#
# Authors:
# Thorsten Passfeld <thorsten.passfeld@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114048");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-12-14 14:31:02 +0100 (Fri, 14 Dec 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Ubiquiti Networks UniFi Video Detection (HTTP)");

  script_tag(name:"summary", value:"Detection of UniFi Video.

  The script sends a connection request to the server and attempts to detect UniFi Video and to
  extract its version if possible.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.ui.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

url = "/";
res = http_get_cache(port: port, item: url);

#Identify and classify the specific type of host
if('content="app-id=com.ubnt.unifivideo">' >< res) {
  hostType = "Session";
} else if('class="portal__controllerItem--unifi-video">' >< res) {
  hostType = "Portal"; #Detected the portal linking to another (internal) host
} else if('window.App = App.initialize({"ENVIRONMENT":"NVR","IS_PRODUCTION":true,"IS_CLOUD_FEATURE_ENABLED":false});' >< res) {
  hostType = "NoSessionEmail";
} else {
  url = "/services/api.js";
  res = http_get_cache(port: port, item: url);
  if('"unifi"===mode&&(mode=0)' >< res)
    hostType = "NoSession";
}

if(!isnull(hostType)) {
  version = "unknown";
  install = "/";

  #Cannot always detect version from here. Only some hosts have it exposed via their protocol on port 10001.
  #For that we already have: gb_ubnt_discovery_protocol_detect.nasl.
  #However, some hosts do expose their version through HTTP.
  res = http_get_cache(port: port, item: "/api/2.0/bootstrap");

  #{"version":"3.9.9",
  ver = eregmatch(pattern: '\\{"version":"([0-9.]+)",', string: res);
  if(!isnull(ver[1]))
    version = ver[1];

  set_kb_item(name: "ubnt/unifi_video/detected", value: TRUE);
  #The hostType is used to classify the different types of hosts from the get-go,
  #so the following related VTs can handle those differently without having to check again.
  set_kb_item(name: "ubnt/unifi_video/hostType", value: hostType);

  cpe = "cpe:/a:ui:unifi_video:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  register_and_report_cpe(app: "UniFi Video",
                          ver: version,
                          concluded: ver[0],
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: install,
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl);
}

exit(0);
