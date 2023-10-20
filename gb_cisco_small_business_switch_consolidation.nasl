# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144402");
  script_version("2023-07-26T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2020-08-17 03:57:05 +0000 (Mon, 17 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Small Business Switch Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Cisco Small Business Switch detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_small_business_switch_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_small_business_switch_http_detect.nasl");
  script_mandatory_keys("cisco/sb_switch/detected");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/solutions/small-business/networking/switches.html");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("cisco/sb_switch/detected"))
  exit(0);

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  model_list = get_kb_list("cisco/sb_switch/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/sb_switch/model", value: detected_model);
      break;
    }
  }

  version_list = get_kb_list("cisco/sb_switch/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Cisco Small Business Switch " + detected_model + " Firmware";
  hw_name = "Cisco Small Business Switch " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:" + tolower(detected_model) +
                     "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cisco:" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:cisco:" + tolower(detected_model);
} else {
  os_name = "Cisco Small Business Switch Unknown Model Firmware";
  hw_name = "Cisco Small Business Switch Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:small_business_switch_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:cisco:small_business_switch_firmware";
  hw_cpe = "cpe:/h:cisco:small_business_switch";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cisco Small Business Switch Detection Consolidation", runs_key: "unixoide" );

if (http_ports = get_kb_list("cisco/sb_switch/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    loc = get_kb_item("cisco/sb_switch/http/" + port + "/location");
    if (!loc)
      loc = location;

    concluded = get_kb_item("cisco/sb_switch/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("cisco/sb_switch/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: os_cpe, location: loc, port: port, service: "www");
    register_product(cpe: hw_cpe, location: loc, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("cisco/sb_switch/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("cisco/sb_switch/snmp/" + port + "/concluded");
    concludedOID  = get_kb_item("cisco/sb_switch/snmp/" + port + "/concludedOID");
    if (concluded) {
      extra += '  Concluded from SNMP banner "' + concluded + '"';
      if (concludedOID)
        extra += ' and version extracted via OID: ' + concludedOID;
      extra += '\n';
    }

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report += build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
