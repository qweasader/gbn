# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106548");
  script_version("2023-07-27T05:05:09+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:09 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC Data Protection Advisor Detection");

  script_tag(name:"summary", value:"Detection of Dell EMC Data Protection Advisor

  The script sends a HTTP connection request to the server and attempts to detect the presence of Dell EMC Data
  Protection Advisor and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.delltechnologies.com/en-us/data-protection/data-protection-advisor.htm");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/");

if ("<title>Data Protection Advisor</title>" >< res && 'description">Server is starting. Please wait.' >< res) {
  version = "unknown";

  vers = eregmatch(pattern: 'var version = "([0-9.]+)', string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    set_kb_item(name: "emc_data_protection_advisor/version", value: version);
  }

  build = eregmatch(pattern: 'var buildNumber = "([0-9]+)', string: res);
  if (!isnull(build[1])) {
    build = build[1];
    set_kb_item(name: "emc_data_protection_advisor/build", value: build);
  }

  set_kb_item(name: "emc_data_protection_advisor/installed", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:dell:emc_data_protection_advisor:");
  if (!cpe)
    cpe = "cpe:/a:dell:emc_data_protection_advisor";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "Dell EMC Data Protection Advisor", version: version, install: "/",
                                           cpe: cpe, concluded: vers[0], extra: "Build: " + build),
              port: port);
  exit(0);
}

exit(0);
