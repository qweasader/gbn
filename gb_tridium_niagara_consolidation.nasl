# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144394");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-08-14 04:07:32 +0000 (Fri, 14 Aug 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Tridium Niagara Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_tridium_niagara_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_tridium_niagara_fox_detect.nasl", "gsf/gb_tridium_niagara_bacnet_detect.nasl");
  script_mandatory_keys("tridium/niagara/detected");

  script_tag(name:"summary", value:"Consolidation of Tridium Niagara detections.");

  script_xref(name:"URL", value:"https://www.tridium.com");

  exit(0);
}

if (!get_kb_item("tridium/niagara/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("fox", "bacnet", "http")) {
  version_list = get_kb_list("tridium/niagara/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:tridium:niagara:");
if (!cpe)
  cpe = "cpe:/a:tridium:niagara";

if (http_ports = get_kb_list("tridium/niagara/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("tridium/niagara/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    register_product(cpe: cpe, location: "/", port: port, service: "www");
  }
}

if (fox_ports = get_kb_list("tridium/niagara/fox/port")) {
  foreach port (fox_ports) {
    extra += "Fox on port " + port + '/tcp\n';

    register_product(cpe: cpe, location: "/", port: port, service: "niagara-fox");
  }
}

if (bacnet_ports = get_kb_list("tridium/niagara/bacnet/port")) {
  foreach port (bacnet_ports) {
    extra += "BACNET on port " + port + '/udp\n';

    register_product(cpe: cpe, location: "/", port: port, proto: "udp", service: "bacnet");
  }
}

report = build_detection_report(app: "Tridium Niagara", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
