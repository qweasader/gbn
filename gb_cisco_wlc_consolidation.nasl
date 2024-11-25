# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105430");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-10-30 14:22:49 +0100 (Fri, 30 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cisco Wireless LAN Controller (WLC) Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Cisco Wireless LAN Controller (WLC) device
  detections.");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_cisco_wlc_snmp_detect.nasl", "gb_cisco_wlc_ssh_login_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_cisco_wlc_http_detect.nasl", "gsf/gb_cisco_wlc_ssh_banner_detect.nasl",
                        "gsf/gb_cisco_wlc_telnet_detect.nasl");
  script_mandatory_keys("cisco/wlc/detected");

  script_xref(name:"URL", value:"https://www.cisco.com/c/en/us/products/wireless/wireless-lan-controller/index.html");

  exit(0);
}

if (!get_kb_item("cisco/wlc/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
location = "/";

foreach source (make_list("ssh-login", "snmp", "http")) {
  version_list = get_kb_list("cisco/wlc/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("cisco/wlc/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "cisco/wlc/model", value: detected_model);
      break;
    }
  }
}

os_cpe1 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:wireless_lan_controller_firmware:");
os_cpe2 = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:cisco:wireless_lan_controller_software:");
if (!os_cpe1) {
  os_cpe1 = "cpe:/o:cisco:wireless_lan_controller_firmware";
  os_cpe2 = "cpe:/o:cisco:wireless_lan_controller_software";
}

if (detected_model != "unknown") {
  os_name = "Cisco Wireless LAN Controller " + detected_model + " Firmware";
  hw_name = "Cisco Wireless LAN Controller " + detected_model;
  os_cpe3 = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                      base: "cpe:/o:cisco:" + tolower(detected_model) + "_wireless_lan_controller_firmware:");
  os_cpe4 = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                      base: "cpe:/o:cisco:" + tolower(detected_model) + "_wireless_lan_controller_software:");
  if (!os_cpe3) {
    os_cpe3 = "cpe:/o:cisco:" + tolower(detected_model) + "_wireless_lan_controller_firmware";
    os_cpe4 = "cpe:/o:cisco:" + tolower(detected_model) + "_wireless_lan_controller_software";
  }

  hw_cpe = "cpe:/h:cisco:" + tolower(detected_model) + "_wireless_lan_controller";
} else {
  os_name = "Cisco Wireless LAN Controller Firmware";
  hw_name = "Cisco Wireless LAN Controller Unknown Model";

  hw_cpe = "cpe:/h:cisco:wireless_lan_controller";
}

os_register_and_report(os: os_name, cpe: os_cpe1, runs_key: "unixoide",
                       desc: "Cisco Wireless LAN Controller (WLC) Detection Consolidation");

if (ssh_login_ports = get_kb_list("cisco/wlc/ssh-login/port")) {
  extra += 'Local Detection over SSH:\n';

  foreach port (ssh_login_ports) {
    concluded = get_kb_item("cisco/wlc/ssh-login/" + port + "/concluded");
    extra += '  Port: ' + port + '/tcp\n';
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded;

    register_product(cpe: os_cpe1, location: location, port: port, service: "ssh-login");
    register_product(cpe: os_cpe2, location: location, port: port, service: "ssh-login");
    if (os_cpe3) {
      register_product(cpe: os_cpe3, location: location, port: port, service: "ssh-login");
      register_product(cpe: os_cpe4, location: location, port: port, service: "ssh-login");
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh-login");
  }
}

if (snmp_ports = get_kb_list("cisco/wlc/snmp/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over SNMP:\n';

  foreach port (snmp_ports) {
    extra += '  Port:                        ' + port + '/udp\n';

    concludedVers = get_kb_item("cisco/wlc/snmp/" + port + "/concludedVers");
    concludedVersOID = get_kb_item("cisco/wlc/snmp/" + port + "/concludedVersOID");
    if (concludedVers && concludedVersOID)
      extra += '  Concluded version from:      "' + concludedVers + '" via OID: "' + concludedVersOID + '"\n';

    concludedMod = get_kb_item("cisco/wlc/snmp/" + port + "/concludedMod");
    concludedModOID = get_kb_item("cisco/wlc/snmp/" + port + "/concludedModOID");
    if (concludedMod && concludedModOID)
      extra += '  Concluded model from:        "' + concludedMod + '" via OID: "' + concludedModOID + '"\n';

    concluded = get_kb_item("cisco/wlc/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from sysDescr OID: ' + concluded;

    register_product(cpe: os_cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: os_cpe2, location: location, port: port, service: "snmp", proto: "udp");
    if (os_cpe3) {
      register_product(cpe: os_cpe3, location: location, port: port, service: "snmp", proto: "udp");
      register_product(cpe: os_cpe4, location: location, port: port, service: "snmp", proto: "udp");
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "snmp", proto: "udp");
  }
}

if (http_ports = get_kb_list("cisco/wlc/http/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over HTTP(s):\n';

  foreach port (http_ports) {
    extra += '  Port: ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/wlc/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded;

    register_product(cpe: os_cpe1, location: location, port: port, service: "www");
    register_product(cpe: os_cpe2, location: location, port: port, service: "www");
    if (os_cpe3) {
      register_product(cpe: os_cpe3, location: location, port: port, service: "www");
      register_product(cpe: os_cpe4, location: location, port: port, service: "www");
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (ssh_banner_ports = get_kb_list("cisco/wlc/ssh-banner/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over SSH:\n';

  foreach port (ssh_banner_ports) {
    extra += '  Port: ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/wlc/ssh-banner/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded;

    register_product(cpe: os_cpe1, location: location, port: port, service: "ssh");
    register_product(cpe: os_cpe2, location: location, port: port, service: "ssh");
    if (os_cpe3) {
      register_product(cpe: os_cpe3, location: location, port: port, service: "ssh");
      register_product(cpe: os_cpe4, location: location, port: port, service: "ssh");
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "ssh");
  }
}

if (telnet_ports = get_kb_list("cisco/wlc/telnet/port")) {
  if (extra)
    extra += '\n\n';

  extra += 'Remote Detection over Telnet:\n';

  foreach port (telnet_ports) {
    extra += '  Port: ' + port + '/tcp\n';

    concluded = get_kb_item("cisco/wlc/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded;

    register_product(cpe: os_cpe1, location: location, port: port, service: "telnet");
    register_product(cpe: os_cpe2, location: location, port: port, service: "telnet");
    if (os_cpe3) {
      register_product(cpe: os_cpe3, location: location, port: port, service: "telnet");
      register_product(cpe: os_cpe4, location: location, port: port, service: "telnet");
    }

    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe1);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
