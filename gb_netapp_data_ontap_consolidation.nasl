# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.141923");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2019-01-25 12:54:35 +0700 (Fri, 25 Jan 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("NetApp Data ONTAP Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of NetApp Data ONTAP detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_netapp_data_ontap_http_detect.nasl", "gb_netapp_data_ontap_ntp_detect.nasl",
                      "gb_netapp_data_ontap_snmp_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_netapp_data_ontap_ftp_detect.nasl", "gsf/gb_netapp_data_ontap_ndmp_detect.nasl",
                        "gsf/gb_netapp_data_ontap_ssh_detect.nasl", "gsf/gb_netapp_data_ontap_telnet_detect.nasl",
                        "gsf/gb_netapp_data_ontap_ssh_login_detect.nasl");
  script_mandatory_keys("netapp_data_ontap/detected");

  script_xref(name:"URL", value:"http://www.netapp.com/us/products/data-management-software/ontap.asp");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("os_func.inc");

if (!get_kb_item("netapp_data_ontap/detected"))
  exit(0);

detected_version = "unknown";

foreach source (make_list("http", "ntp", "snmp", "ssh-login", "ndmp", "telnet", "ssh", "ftp")) {
  version_list = get_kb_list("netapp_data_ontap/" + source + "/*/version");
  foreach vers (version_list) {
    if (vers != "unknown" && detected_version == "unknown")
      detected_version = vers;
  }
}

cpe = build_cpe(value: tolower(detected_version), exp: "^([0-9p.]+)", base: "cpe:/o:netapp:data_ontap:");
if (!cpe)
  cpe = 'cpe:/o:netapp:data_ontap';

if (http_ports = get_kb_list("netapp_data_ontap/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/http/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "www");
  }
}

if (ntp_ports = get_kb_list("netapp_data_ontap/ntp/port")) {
  foreach port (ntp_ports) {
    extra += 'NTP on port ' + port + '/udp\n';

    concluded = get_kb_item("netapp_data_ontap/ntp/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from NTP system banner: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ntp", proto: "udp");
  }
}

if (snmp_ports = get_kb_list("netapp_data_ontap/snmp/port")) {
  foreach port (snmp_ports) {
    extra += 'SNMP on port ' + port + '/udp\n';

    concluded = get_kb_item("netapp_data_ontap/snmp/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from SNMP sysDescr OID: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "snmp", proto: "udp");
  }
}

if (ndmp_ports = get_kb_list("netapp_data_ontap/ndmp/port")) {
  foreach port (ndmp_ports) {
    extra += 'NDMP on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/ndmp/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from NDMP host info: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ndmp");
  }
}

if (telnet_ports = get_kb_list("netapp_data_ontap/telnet/port")) {
  foreach port (telnet_ports) {
    extra += 'Telnet banner on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/telnet/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "telnet");
  }
}

if (ssh_ports = get_kb_list("netapp_data_ontap/ssh/port")) {
  foreach port (ssh_ports) {
    extra += 'SSH banner on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/ssh/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ssh");
  }
}

if (ftp_ports = get_kb_list("netapp_data_ontap/ftp/port")) {
  foreach port (ftp_ports) {
    extra += 'FTP banner on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/ftp/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded from: ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ftp");
  }
}

if (ssh_login_ports = get_kb_list("netapp_data_ontap/ssh-login/port")) {
  foreach port (ssh_login_ports) {
    extra += 'SSH login on port ' + port + '/tcp\n';

    concluded = get_kb_item("netapp_data_ontap/ssh-login/" + port + "/concluded");
    if (concluded)
      extra += 'Concluded ' + concluded + '\n';

    register_product(cpe: cpe, location: '/', port: port, service: "ssh-login");
  }
}

os_register_and_report(os: "NetApp Data ONTAP", cpe: cpe, desc: "NetApp Data ONTAP Detection Consolidation", runs_key:"unixoide" );

report = build_detection_report(app: "NetApp Data ONTAP", version: detected_version, cpe: cpe, install: "/");

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\r\n' + extra;
}

if (report)
  log_message(port: 0, data: report);

exit(0);
