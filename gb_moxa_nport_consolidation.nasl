# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.145968");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2021-05-19 04:08:38 +0000 (Wed, 19 May 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Moxa NPort Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Moxa NPort device detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_moxa_nport_telnet_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_moxa_nport_http_detect.nasl");
  script_mandatory_keys("moxa/nport/detected");

  script_xref(name:"URL", value:"https://www.moxa.com");

  exit(0);
}

if (!get_kb_item("moxa/nport/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

detected_model = "unknown";
detected_version = "unknown";
detected_build = "unknown";
location = "/";

foreach source (make_list("telnet", "http")) {
  version_list = get_kb_list("moxa/nport/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  model_list = get_kb_list("moxa/nport/" + source + "/*/model");
  foreach model (model_list) {
    if (model != "unknown" && detected_model == "unknown") {
      detected_model = model;
      break;
    }
  }

  build_list = get_kb_list("moxa/nport/" + source + "/*/build");
  foreach build (build_list) {
    if (build != "unknown" && detected_build == "unknown") {
      detected_build = build;
      set_kb_item(name: "moxa/nport/build", value: detected_build);
      break;
    }
  }
}

if (detected_model != "unknown") {
  os_name = "Moxa NPort " + detected_model + " Firmware";
  hw_name = "Moxa NPort " + detected_model;

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)",
                     base: "cpe:/o:moxa:nport_" + tolower(detected_model) + "_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:nport_" + tolower(detected_model) + "_firmware";

  hw_cpe = "cpe:/h:moxa:nport_" + tolower(detected_model);
} else {
  os_name = "Moxa NPort Unknown Model Firmware";
  hw_name = "Moxa Nport Unknown Model";

  os_cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/o:moxa:nport_firmware:");
  if (!os_cpe)
    os_cpe = "cpe:/o:moxa:nport_firmware";

  hw_cpe = "cpe:/h:moxa:nport";
}

os_register_and_report(os: os_name, cpe: os_cpe, desc: "Moxa NPort Detection Consolidation", runs_key: "unixoide");

if (http_ports = get_kb_list("moxa/nport/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("moxa/nport/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "www");
    register_product(cpe: hw_cpe, location: location, port: port, service: "www");
  }
}

if (telnet_ports = get_kb_list("moxa/nport/telnet/port")) {
  foreach port (telnet_ports) {
    extra += 'Telnet on port ' + port + '/tcp\n';

    concluded = get_kb_item("moxa/nport/telnet/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from banner:\n' + concluded + '\n';

    register_product(cpe: os_cpe, location: location, port: port, service: "telnet");
    register_product(cpe: hw_cpe, location: location, port: port, service: "telnet");
  }
}

report  = build_detection_report(app: os_name, version: detected_version, install: location, cpe: os_cpe,
                                 extra: "Build: " + detected_build);
report += '\n\n';
report += build_detection_report(app: hw_name, skip_version: TRUE, install: location, cpe: hw_cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
