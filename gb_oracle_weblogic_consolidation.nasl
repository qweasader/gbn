# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

include("plugin_feed_info.inc");

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143747");
  script_version("2024-07-03T06:48:05+0000");
  script_tag(name:"last_modification", value:"2024-07-03 06:48:05 +0000 (Wed, 03 Jul 2024)");
  script_tag(name:"creation_date", value:"2020-04-22 08:45:56 +0000 (Wed, 22 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Oracle WebLogic Server Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_oracle_weblogic_http_detect.nasl");
  if(FEED_NAME == "GSF" || FEED_NAME == "GEF" || FEED_NAME == "SCM")
    script_dependencies("gsf/gb_oracle_weblogic_t3_detect.nasl");
  script_mandatory_keys("oracle/weblogic/detected");

  script_xref(name:"URL", value:"https://www.oracle.com/middleware/weblogic/");

  script_tag(name:"summary", value:"Consolidation of Oracle WebLogic detections.");

  exit(0);
}

if (!get_kb_item("oracle/weblogic/detected"))
  exit(0);

include("host_details.inc");

detected_version = "unknown";
detected_servicepack = "unknown";
location = "/";

foreach source (make_list("http", "t3")) {
  version_list = get_kb_list("oracle/weblogic/" + source + "/*/version");
  foreach version (version_list) {
    if (version != "unknown" && detected_version == "unknown") {
      detected_version = version;
      break;
    }
  }

  sp_list = get_kb_list("oracle/weblogic/" + source + "/*/servicepack");
  foreach servicepack (sp_list) {
    if (servicepack != "unknown" && detected_servicepack == "unknown") {
      detected_servicepack = servicepack;
      break;
    }
  }
}

cpe1 = "cpe:/a:bea:weblogic_server";
cpe2 = "cpe:/a:oracle:weblogic_server";

if (detected_version != "unknown") {
  cpe1 += ":" + detected_version;
  cpe2 += ":" + detected_version;

  if (detected_servicepack != "unknown") {
    cpe1 += ":sp" + detected_servicepack;
    cpe2 += ":sp" + detected_servicepack;
    detected_version += " SP" + detected_servicepack;
  }
}

if (http_ports = get_kb_list("oracle/weblogic/http/port")) {
  foreach port (http_ports) {
    extra += "HTTP(s) on port " + port + '/tcp\n';

    concluded = get_kb_item("oracle/weblogic/http/" + port + "/concluded");
    if (concluded)
      extra += "  Concluded from version/product identification result: " + concluded + '\n';

    concUrl = get_kb_item("oracle/weblogic/http/" + port + "/concludedUrl");
    if (concUrl)
      extra += "  Concluded from version/product identification location: " + concUrl + '\n';

    found_services_urls = get_kb_list("oracle/weblogic/http/" + port + "/found_service_urls");
    if (!isnull(found_services_urls)) {
      extra += '  The following Web-Services have been identified at this port:\n';
      found_services_urls = sort(found_services_urls);
      foreach found_services_url (found_services_urls)
        extra += '    ' + found_services_url + '\n';
    }

    register_product(cpe: cpe1, location: location, port: port, service: "www");
    register_product(cpe: cpe2, location: location, port: port, service: "www");
  }
}

if (t3_ports = get_kb_list("oracle/weblogic/t3/port")) {
  foreach port (t3_ports) {
    extra += "T3(S) on port " + port + '/tcp\n';

    concluded = get_kb_item("oracle/weblogic/t3/" + port + "/concluded");
    if (concluded)
      extra += '  Concluded from version/product identification result:\n' + concluded + '\n';

    register_product(cpe: cpe1, location: location, port: port, service: "weblogic-t3");
    register_product(cpe: cpe2, location: location, port: port, service: "weblogic-t3");
  }
}

report  = build_detection_report(app: "Oracle WebLogic Server", version: detected_version, install: location,
                                 cpe: cpe2);

if (extra) {
  report += '\n\nDetection methods:\n';
  report += '\n' + chomp(extra);
}

log_message(port: 0, data: report);

exit(0);
