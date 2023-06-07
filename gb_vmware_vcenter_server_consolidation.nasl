# Copyright (C) 2021 Greenbone Networks GmbH
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

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145661");
  script_version("2022-12-01T10:11:22+0000");
  script_tag(name:"last_modification", value:"2022-12-01 10:11:22 +0000 (Thu, 01 Dec 2022)");
  script_tag(name:"creation_date", value:"2021-03-26 08:32:27 +0000 (Fri, 26 Mar 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("VMware vCenter Server Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of VMware vCenter Server detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_vmware_vcenter_server_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_vmware_vcenter_server_ssh_banner_detect.nasl");
  script_mandatory_keys("vmware/vcenter/server/detected");

  script_xref(name:"URL", value:"https://www.vmware.com/products/vcenter-server.html");

  exit(0);
}

if (!get_kb_item("vmware/vcenter/server/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("http", "ssh")) {
  version_list = get_kb_list("vmware/vcenter/server/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  build_list = get_kb_list("vmware/vcenter/server/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "vmware/vcenter/server/build", value: detected_build);
      set_kb_item(name: "vmware/vcenter/server/build/source", value: source);
      break;
    }
  }
}

cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vcenter_server:");
cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:vmware:vcenter:");
if (!cpe1) {
  cpe1 = "cpe:/a:vmware:vcenter_server";
  cpe2 = "cpe:/a:vmware:vcenter";
}

if (http_ports = get_kb_list("vmware/vcenter/server/http/port")) {
   foreach port (http_ports) {
     extra += 'HTTP(s) on port ' + port + '/tcp\n';

     concluded = get_kb_item("vmware/vcenter/server/http/" + port + "/concluded");
     concUrl = get_kb_item("vmware/vcenter/server/http/" + port + "/concludedUrl");
     if (concluded)
       extra += '  Concluded from version/product identification result: ' + concluded + '\n';

     if (concUrl)
       extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

     register_product(cpe: cpe1, location: location, port: port, service: "www");
     register_product(cpe: cpe2, location: location, port: port, service: "www");
   }
}

if (ssh_ports = get_kb_list("vmware/vcenter/server/ssh/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH on port ' + port + '/tcp\n';

    concluded = get_kb_item("vmware/vcenter/server/ssh/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from SSH banner: ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "ssh");
    register_product(cpe: cpe2, location: location, port: port, service: "ssh");
  }
}

report = build_detection_report(app: "VMware vCenter Server", version: detected_version, build: detected_build,
                                install: location, cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
