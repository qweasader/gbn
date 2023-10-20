# Copyright (C) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.106096");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2016-06-15 15:30:33 +0700 (Wed, 15 Jun 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Siemens SIMATIC S7 Device Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Siemens SIMATIC S7 device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_siemens_simatic_s7_cotp_detect.nasl", "gb_siemens_simatic_s7_snmp_detect.nasl",
                      "gb_siemens_simatic_s7_http_detect.nasl");
  script_mandatory_keys("siemens/simatic_s7/detected");

  script_xref(name:"URL", value:"https://www.siemens.com/global/en/home/products/automation/systems/industrial/plc.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("siemens/simatic_s7/detected"))
  exit(0);

detected_version = "unknown";
detected_model   = "unknown";

# Version
foreach source (make_list("cotp", "snmp", "http")) {
  if (detected_version != "unknown")
    break;

  version_list = get_kb_list("siemens/simatic_s7/" + source + "/*/version");
  foreach version (version_list) {
    if (version) {
      detected_version = version;
      set_kb_item(name: "siemens/simatic_s7/version", value: version);
    }
  }
}

# Model
foreach source (make_list("cotp", "snmp", "http")) {
  if (detected_model != "unknown")
    break;

  model_list = get_kb_list("siemens/simatic_s7/" + source + "/model");
  foreach model (model_list) {
    if (model) {
      detected_model = model;
      set_kb_item(name: "siemens/simatic_s7/model", value: model);
    }
  }
}

# CPE
if (detected_model != "unknown") {
  app_name = "Siemens SIMATIC S7 " + detected_model;

  cpe_model = tolower(ereg_replace(pattern: "[ /]", string: detected_model, replace: "_"));

  app_cpe = build_cpe(value: detected_version, exp:"^([0-9.]+)",
                      base: "cpe:/a:siemens:simatic_s7_" + cpe_model + ":");
  if (!app_cpe)
    app_cpe = "cpe:/a:siemens:simatic_s7_" + cpe_model;

  os_cpe = build_cpe(value: detected_version, exp:"^([0-9.]+)",
                     base: "cpe:/o:siemens:simatic_s7_cpu_" + cpe_model + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:siemens:simatic_s7_cpu_" + cpe_model + "_firmware";
}
else {
  app_name = "Siemens SIMATIC S7 Unknown Model";

  if (detected_version != "unknown") {
    app_cpe = "cpe:/a:siemens:simatic_s7:" + detected_version;
    os_cpe = "cpe:/o:siemens:simatic_s7_cpu_firmware:" + detected_version;
  }
  else {
    app_cpe = "cpe:/a:siemens:simatic_s7";
    os_cpe = "cpe:/o:siemens:simatic_s7_cpu_firmware";
  }
}

# COTP
if (cotp_ports = get_kb_list("siemens/simatic_s7/cotp/port")) {
  foreach port (cotp_ports) {
    extra += 'COTP on port ' + port + '/tcp\n';

    mod_type = get_kb_item("siemens/simatic_s7/cotp/modtype");
    if (mod_type) {
      extra += '  Module Type:   ' + mod_type + '\n';
      replace_kb_item(name: "siemens/simatic_s7/modtype", value: mod_type);
    }

    module = get_kb_item("siemens/simatic_s7/cotp/module");
    if (module)
      extra += '  Module:        ' + module + '\n';

    register_product(cpe: app_cpe, location: port + "/tcp", port: port, service: "cotp");
    register_product(cpe: os_cpe, location: port + "/tcp", port: port, service: "cotp");
  }
}

# SNMP
if (snmp_ports = get_kb_list("siemens/simatic_s7/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    mod_type = get_kb_item("siemens/simatic_s7/snmp/modtype");
    if (mod_type) {
      extra += '  Module Type:   ' + mod_type + '\n';
      replace_kb_item(name: "siemens/simatic_s7/modtype", value: mod_type);
    }

    module = get_kb_item("siemens/simatic_s7/snmp/module");
    if (module)
      extra += '  Module:        ' + module + '\n';

    register_product(cpe: app_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe, location: port + "/udp", port: port, service: "snmp", proto: "udp");
  }
}

# HTTP
if (http_ports = get_kb_list("siemens/simatic_s7/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    mod_type = get_kb_item("siemens/simatic_s7/http/modtype");
    if (mod_type) {
      extra += '  Module Type:   ' + mod_type + '\n';
      replace_kb_item(name: "siemens/simatic_s7/modtype", value: mod_type);
    }

    module = get_kb_item("siemens/simatic_s7/http/module");
    if (module)
      extra += '  Module:        ' + module + '\n';

    concluded = get_kb_item("siemens/simatic_s7/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    concludedurl = get_kb_item("siemens/simatic_s7/http/" + port + "/concludedurl");
    if (concludedurl)
      extra += '  Concluded from version/product identification location:\n' + concludedurl + '\n';

    register_product(cpe: app_cpe, location: "/", port: port, service: "www");
    register_product(cpe: os_cpe, location: "/", port: port, service: "www");
  }
}

# We don't want to register a S7 Firmware as the operating systems as it would
# overwrite our previously more detailed Windows Detections. Examples are e.g.
# module: S7 SoftPLC UA
# modtype: IE_CP   OPC Server
if ("SoftPLC" >!< extra ) {
  os_register_and_report(os: "Siemens SIMATIC S7 CPU Firmware", cpe: os_cpe,
                         desc: "Siemens SIMATIC S7 Device Detection Consolidation", runs_key:"unixoide");
}

report = build_detection_report(app: app_name, version: detected_version,
                                install: "/", cpe: app_cpe);
if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
