# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142490");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-06-05 02:35:07 +0000 (Wed, 05 Jun 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SolarWinds Serv-U Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of SolarWinds Serv-U detections.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_solarwinds_serv-u_ftp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_solarwinds_serv-u_ssh_detect.nasl",
                        "gsf/gb_solarwinds_serv-u_http_detect.nasl");
  script_mandatory_keys("solarwinds/servu/detected");

  script_xref(name:"URL", value:"https://www.serv-u.com/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");

if (!get_kb_item("solarwinds/servu/detected"))
  exit(0);

detected_version = "unknown";
install = "/";

foreach source (make_list("http", "ssh", "ftp")) {
  version_list = get_kb_list("solarwinds/servu/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown") {
      detected_version = vers;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:serv-u:serv-u:");
if (!cpe)
  cpe = "cpe:/a:serv-u:serv-u";

if (http_ports = get_kb_list("solarwinds/servu/http/port")) {

  extra += '\nRemote Detection over HTTP(s):\n';

  foreach port (http_ports) {

    extra += "  Port:      " + port + '/tcp\n';

    concluded = get_kb_item("solarwinds/servu/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded:\n' + concluded + '\n';

    concludedUrl = get_kb_item("solarwinds/servu/http/" + port + "/concludedUrl");
    if (concludedUrl)
      extra += '  Concluded URL(s):\n' + concludedUrl + '\n';

    register_product(cpe: cpe, location: install, port: port, service: "www");
  }
}

if (ssh_ports = get_kb_list("solarwinds/servu/ssh/port")) {

  extra += '\nRemote Detection over SSH:\n';

  foreach port (ssh_ports) {
    concluded = get_kb_item("solarwinds/servu/ssh/" + port + "/concluded");
    extra += "  Port:      " + port + '/tcp\n';
    if (concluded)
      extra += "  Concluded: " + concluded + '\n';

    register_product(cpe: cpe, location: install, port: port, service: "ssh");
  }
}

if (ftp_ports = get_kb_list("solarwinds/servu/ftp/port")) {

  extra += '\nRemote Detection over FTP:\n';

  foreach port (ftp_ports) {
    concluded = get_kb_item("solarwinds/servu/ftp/" + port + "/concluded");
    extra += "  Port:      " + port + '/tcp\n';
    if (concluded)
      extra += "  Concluded: " + concluded + '\n';

    register_product(cpe: cpe, location: install, port: port, service: "ftp");
  }
}

report = build_detection_report(app: "SolarWinds Serv-U", version: detected_version, cpe: cpe, install: install);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += extra;
}

if (report)
  log_message(port: 0, data: chomp(report));

exit(0);
