# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143776");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-28 06:42:59 +0000 (Tue, 28 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Apache ActiveMQ Detection Consolidation");

  script_tag(name:"summary", value:"Consolidation of Apache ActiveMQ detections.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_apache_activemq_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_apache_activemq_stomp_detect.nasl", "gsf/gb_apache_activemq_jms_detect.nasl");
  script_mandatory_keys("apache/activemq/detected");

  script_xref(name:"URL", value:"https://activemq.apache.org/");

  exit(0);
}

if (!get_kb_item("apache/activemq/detected"))
  exit(0);

include("cpe.inc");
include("host_details.inc");

detected_version = "unknown";
location = "/";

foreach source (make_list("stomp", "jms", "http")) {
  version_list = get_kb_list("apache/activemq/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }
}

cpe = build_cpe(value: detected_version, exp: "^([0-9.]+)", base: "cpe:/a:apache:activemq:");
if (!cpe)
  cpe = "cpe:/a:apache:activemq";

if (http_ports = get_kb_list("apache/activemq/http/port")) {
  foreach port (http_ports) {
    extra += 'HTTP(s) on port ' + port + '/tcp\n';

    concluded = get_kb_item("apache/activemq/http/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    concUrl = get_kb_item("apache/activemq/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += '  Concluded from version/product identification location: ' + concUrl + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "www");
  }
}

if (jms_ports = get_kb_list("apache/activemq/jms/port")) {
  foreach port (jms_ports) {
    extra += 'JMS on port ' + port + '/tcp\n';

    concluded = get_kb_item("apache/activemq/jms/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "activemq_jms");
  }
}

if (stomp_ports = get_kb_list("apache/activemq/stomp/port")) {
  foreach port (stomp_ports) {
    extra += 'STOMP on port ' + port + '/tcp\n';

    concluded = get_kb_item("apache/activemq/stomp/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result: ' + concluded + '\n';

    register_product(cpe: cpe, location: location, port: port, service: "stomp");
  }
}

report  = build_detection_report(app: "Apache ActiveMQ", version: detected_version, install: location, cpe: cpe);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + extra;
}

log_message(port: 0, data: report);

exit(0);
