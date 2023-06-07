# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113662");
  script_version("2022-11-25T10:12:49+0000");
  script_tag(name:"last_modification", value:"2022-11-25 10:12:49 +0000 (Fri, 25 Nov 2022)");
  script_tag(name:"creation_date", value:"2020-03-30 14:56:55 +0100 (Mon, 30 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Wowza Streaming Engine Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_wowza_streaming_engine_http_detect.nasl",
                      "gb_wowza_streaming_engine_rtsp_detect.nasl",
                      "gb_wowza_streaming_engine_manager_http_detect.nasl");
  script_mandatory_keys("wowza_streaming_engine/detected");

  script_tag(name:"summary", value:"Consolidation of Wowza Streaming Engine detections.");

  script_xref(name:"URL", value:"https://www.wowza.com/products/streaming-engine");

  exit(0);
}

if (!get_kb_item("wowza_streaming_engine/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("rtsp", "http")) {
  version_list = get_kb_list("wowza_streaming_engine/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "([0-9.]+)", base: "cpe:/a:wowza:streaming_engine:");
if (!cpe)
  cpe = "cpe:/a:wowza:streaming_engine";

if (rtsp_ports = get_kb_list("wowza_streaming_engine/rtsp/port")) {
  foreach port (rtsp_ports) {
    extra += 'RTSP on port ' + port + '/tcp\n';

    concluded = get_kb_item("wowza_streaming_engine/rtsp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "rtsp");
  }
}

if (http_ports = get_kb_list("wowza_streaming_engine/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("wowza_streaming_engine/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (manager_ports = get_kb_list("wowza_streaming_engine/http-manager/port")) {
  foreach port (manager_ports) {
    extra += 'HTTP(s) Manager on port ' + port + '/tcp\n';

    concludedUrl = get_kb_item("wowza_streaming_engine/http-manager/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded from version/product identification location: ' + concludedUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www-admin");
  }
}

report = build_detection_report(app: "Wowza Streaming Engine", version: detected_version,
                                install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
