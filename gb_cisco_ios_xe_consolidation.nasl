# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105659");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2016-05-09 15:46:47 +0200 (Mon, 09 May 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco IOS XE Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_cisco_ios_xe_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_ios_xe_snmp_detect.nasl",
                        "gsf/gb_cisco_ios_xe_http_detect.nasl");
  script_mandatory_keys("cisco/ios_xe/detected");

  script_tag(name:"summary", value:"Consolidation of Cisco IOS XE detections.");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/ios-nx-os-software/ios-xe/index.html");

  exit(0);
}

if (!get_kb_item("cisco/ios_xe/detected"))
  exit(0);

include("cisco_ios.inc");
include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_image = "unknown";
location = "/";
os_name = "Cisco IOS XE";

# nb: Currently only via SSH login and SNMP extracted
foreach source (make_list("ssh-login", "snmp")) {
  version_list = get_kb_list("cisco/ios_xe/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = iosver_2_iosxe_ver(iosver: version);
      break;
    }
  }

  model_list = get_kb_list("cisco/ios_xe/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/ios_xe/model", value: detected_model);
      break;
    }
  }

  image_list = get_kb_list("cisco/ios_xe/" + source + "/*/image");
  foreach image (image_list) {
    if (image != "unknown" && detected_image == "unknown") {
      detected_image = image;
      set_kb_item(name: "cisco/ios_xe/image", value: detected_image);
      break;
    }
  }
}

os_cpe = build_cpe(value: detected_version, exp: "^([0-9A-Z.]+)", base: "cpe:/o:cisco:ios_xe:");
if (!os_cpe)
  os_cpe = "cpe:/o:cisco:ios_xe";

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Cisco IOS XE Detection Consolidation", runs_key: "unixoide");

if (detected_model != "unknown") {
  os_name += " on " + detected_model;
  hw_cpe = "cpe:/h:cisco:" + str_replace(string: tolower(detected_model), find: " ", replace: "_");
}

if (snmp_ports = get_kb_list("cisco/ios_xe/snmp/port")) {
  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    extra += '  Port:                ' + port + '/udp\n';

    concludedVers = get_kb_item("cisco/ios_xe/snmp/" + port + "/concludedVers");
    concludedVersOID = get_kb_item("cisco/ios_xe/snmp/" + port + "/concludedVersOID");
    if (concludedVers && concludedVersOID)
      extra += '  Concluded from:      "' + concludedVers + '" via OID: "' + concludedVersOID + '"\n';

    concluded = get_kb_item("cisco/ios_xe/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner:\n' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "snmp", proto: "udp");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("cisco/ios_xe/http/port")) {
  extra += 'Remote Detection over HTTP:\n';

  foreach port (http_ports) {
    extra += "  Port:                " + port + '/tcp\n';

    concludedUrl = get_kb_item("cisco/ios_xe/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += "  Concluded from version/product identification location: " + concludedUrl + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (ssh_login_ports = get_kb_list("cisco/ios_xe/ssh-login/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    concluded = get_kb_item("cisco/ios_xe/ssh-login/" + port + "/concluded");
    extra += '  Port:                           ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded;

    register_product(cpe: os_cpe, location: location, port: port, service: "ssh-login");
    if (hw_cpe)
      register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe);
if (hw_cpe) {
  report += '\n\n';
  report += build_detection_report(app: "Cisco " + detected_model, skip_version: TRUE, install: location, cpe: hw_cpe);
}

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
