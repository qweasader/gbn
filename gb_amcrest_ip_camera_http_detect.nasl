# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.114084");
  script_version("2021-11-23T14:13:02+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-11-23 14:13:02 +0000 (Tue, 23 Nov 2021)");
  script_tag(name:"creation_date", value:"2019-03-15 14:31:11 +0100 (Fri, 15 Mar 2019)");
  script_name("Amcrest Technologies IP Camera Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Amcrest's IP Camera software / web
  interface.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("os_func.inc");

#Note: This software is very similar to Dahua's -> gb_dahua_devices_http_detect.nasl and related VTs

port = http_get_port(default: 8080);

url = "/custom_lang/English.txt";

res = http_get_cache(port: port, item: url);

if(res =~ "Copyright\s*[0-9]+\s*Amcrest\s*Technologies" && "w_camera_info" >< res) {

  #Version detection requires login.
  version = "unknown";

  set_kb_item(name: "amcrest/ip_camera/detected", value: TRUE);
  set_kb_item(name: "amcrest/ip_camera/http/detected", value: TRUE);
  set_kb_item(name: "amcrest/ip_camera/" + port + "/detected", value: TRUE);

  os_register_and_report(os: "Linux/Unix (Embedded)", cpe: "cpe:/o:linux:kernel",
                         port: port, desc: "Amcrest Technologies IP Camera Detection (HTTP)",
                         runs_key: "unixoide");

  cpe = "cpe:/a:amcrest:ip_camera:";

  conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  register_and_report_cpe(app: "Amcrest Technologies IP Camera",
                          ver: version,
                          base: cpe,
                          expr: "^([0-9.]+)",
                          insloc: "/",
                          regPort: port,
                          regService: "www",
                          conclUrl: conclUrl,
                          extra: "Version detection requires login.");
}

exit(0);