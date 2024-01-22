# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144350");
  script_version("2024-01-18T05:07:09+0000");
  script_tag(name:"last_modification", value:"2024-01-18 05:07:09 +0000 (Thu, 18 Jan 2024)");
  script_tag(name:"creation_date", value:"2020-08-04 05:14:24 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pulse Secure / Ivanti Connect Secure Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_pulse_connect_secure_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_pulse_connect_secure_http_detect.nasl");
  script_mandatory_keys("pulsesecure/detected");

  script_tag(name:"summary", value:"Consolidation of Ivanti Connect Secure (formerly Pulse Secure
  Connect Secure) detections.");

  script_xref(name:"URL", value:"https://www.ivanti.com/products/connect-secure-vpn");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("pulsesecure/detected"))
  exit(0);

detected_version = "unknown";
detected_model = "unknown";
location = "/";

foreach source (make_list("snmp", "http")) {
  version_list = get_kb_list("pulsesecure/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("pulsesecure/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      set_kb_item(name: "pulsesecure/model", value: detected_model);
      break;
    }
  }
}

name = "Pulse Secure / Ivanti Connect Secure";
if (detected_model != "unknown")
  name += " on " + detected_model;

# The most recent vendor is Ivanti
cpe1 = build_cpe(value: tolower(detected_version), exp: "^([0-9R.]+)", base: "cpe:/a:ivanti:connect_secure:");
# After Juniper the second vendor was Pulse Secure:
# https://www.juniper.net/documentation/en_US/release-independent/junos-pulse/information-products/pathway-pages/junos-pulse/index.html
cpe2 = build_cpe(value: tolower(detected_version), exp: "^([0-9R.]+)", base: "cpe:/a:pulsesecure:pulse_connect_secure:");
# Earlier Juniper Product, formerly Juniper Junos Pulse, cpe:/a:juniper:pulse_connect_secure
cpe3 = build_cpe(value: tolower(detected_version), exp: "^([0-9R.]+)", base: "cpe:/a:juniper:pulse_connect_secure:");
if (!cpe1) {
  cpe1 = "cpe:/a:ivanti:connect_secure";
  cpe2 = "cpe:/a:pulsesecure:pulse_connect_secure";
  cpe3 = "cpe:/a:juniper:pulse_connect_secure";
}

# The appliance/server runs only on Linux based systems.
os_register_and_report(os: "Linux", cpe: "cpe:/o:linux:kernel", desc: "Pulse Secure / Ivanti Connect Secure Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("pulsesecure/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    conclUrl = get_kb_item("pulsesecure/http/" + port + "/concludedUrl");
    if (conclUrl)
      extra += '  Concluded from version/product identification location:\n' + conclUrl + '\n';

    concluded = get_kb_item("pulsesecure/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "www");
    register_product(cpe: cpe2, location: location, port: port, service: "www");
    register_product(cpe: cpe3, location: location, port: port, service: "www");
  }
}

if (snmp_ports = get_kb_list("pulsesecure/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';
    concluded = get_kb_item("pulsesecure/snmp/" + port + "/concluded");
    if (concluded)
      extra += '  SNMP Banner:  ' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: cpe2, location: location, port: port, service: "snmp", proto: "udp");
    register_product(cpe: cpe3, location: location, port: port, service: "snmp", proto: "udp");
  }
}

report = build_detection_report(app: name, version: detected_version, install: location, cpe: cpe1);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: chomp(report));

exit(0);
