###############################################################################
# OpenVAS Vulnerability Test
#
# Brickcom Network Camera Detection
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.112339");
  script_version("2021-04-15T13:23:31+0000");
  script_tag(name:"last_modification", value:"2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)");
  script_tag(name:"creation_date", value:"2018-07-26 16:22:11 +0200 (Thu, 26 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Brickcom Network Camera Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Brickcom/banner");

  script_tag(name:"summary", value:"Detection of Brickcom Network Camera devices.");

  script_xref(name:"URL", value:"https://www.brickcom.com/");

  exit(0);
}

include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);
banner = http_get_remote_headers(port: port);

if(banner = egrep(string: banner, pattern: 'www-authenticate\\s*:\\s*basic\\s+realm\\s*=\\s*"brickcom', icase: TRUE)) {

  banner = chomp(banner);

  set_kb_item(name: "brickcom/network_camera/detected", value: TRUE);
  set_kb_item(name: "brickcom/network_camera/http_port", value: port);

  version = "unknown";
  install = port + "/tcp";

  model_match = eregmatch(pattern: 'www-authenticate\\s*:\\s*basic\\s+realm\\s*=\\s*"brickcom ([A-Za-z0-9-]+)"', string: banner, icase: TRUE);
  if(model_match[1]) {
    model   = model_match[1];
    hw_cpe  = "cpe:/h:brickcom:" + tolower(model);
    hw_name = "Brickcom " + model + " Network Camera";
    os_cpe  = "cpe:/o:brickcom:" + tolower(model) + "_firmware";
    os_name = "Brickcom " + model + " Network Camera Firmware";
    set_kb_item(name: "brickcom/network_camera/model", value: model);
  } else {
    hw_cpe  = "cpe:/h:brickcom:network_camera";
    hw_name = "Brickcom Unknown Model Network Camera";
    os_cpe  = "cpe:/o:brickcom:network_camera_firmware";
    os_name = "Brickcom Unknown Model Network Camera Firmware";
  }

  os_register_and_report(os: os_name, cpe: os_cpe, desc: "Brickcom Network Camera Detection (HTTP)", runs_key: "unixoide");

  report += build_detection_report(app: hw_name,
                                   install: install,
                                   skip_version: TRUE,
                                   cpe: hw_cpe);

  report += '\n\n';
  report += build_detection_report(app: os_name,
                                   install: install,
                                   version: version,
                                   cpe: os_cpe);
  report += '\n\nConcluded from HTTP banner on port ' + install + ': ' + banner;

  log_message(port: port, data: report);
}

exit(0);
