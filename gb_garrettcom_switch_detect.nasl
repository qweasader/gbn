# Copyright (C) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106833");
  script_version("2021-04-26T08:59:41+0000");
  script_tag(name:"last_modification", value:"2021-04-26 08:59:41 +0000 (Mon, 26 Apr 2021)");
  script_tag(name:"creation_date", value:"2017-05-26 15:04:01 +0700 (Fri, 26 May 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Belden GarrettCom Switch Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Belden GarrettCom Switches.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.belden.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

res = http_get_cache(port: port, item: "/gc/flash.php");

if (res =~ 'CONTENT="Copyright .c. .... Garrettcom"' && "<title>GarrettCom" >< res) {
  version = "unknown";

  model = eregmatch(pattern: "<title>GarrettCom ([^ ]+)", string: res);
  if (isnull(model[1]))
    exit(0);

  set_kb_item(name: "garretcom_switch/detected", value: TRUE);
  set_kb_item(name: "garretcom_switch/model", value: model[1]);

  cpe = "cpe:/o:garrettcom:" + tolower(model[1]);

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  os_register_and_report(os: "Belden GarretCom Switch Firmware", cpe: cpe,
                         desc: "Belden GarrettCom Switch Detection (HTTP)", runs_key: "unixoide");

  log_message(data: build_detection_report(app: "Belden GarrettCom " + model[1] + " Switch", version: version,
                                           install: port + "/tcp", cpe: cpe),
              port: port);
  exit(0);
}

exit(0);
