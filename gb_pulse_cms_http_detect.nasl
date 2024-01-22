# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.146168");
  script_version("2023-12-13T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-12-13 05:05:23 +0000 (Wed, 13 Dec 2023)");
  script_tag(name:"creation_date", value:"2021-06-23 08:15:54 +0000 (Wed, 23 Jun 2021)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Pulse CMS Detection (HTTP)");

  script_tag(name:"summary", value:"HTTP based detection of Pulse CMS.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "gb_php_http_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://www.pulsecms.com");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 80);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/cms", "/pulsecms", "/PulseCMS", http_cgi_dirs(port: port))) {
  install = dir;

  if (dir == "/")
    dir = "";

  url1 = dir + "/admin/index.php";
  res1 = http_get_cache(port: port, item: url1);

  url2 = dir + "/index.php";
  res2 = http_get_cache(port: port, item: url2);

  if (!res1 && !res2)
    continue;

  if (res1 =~ "^HTTP/1\.[01] 200" && "<title>Pulse CMS</title>" >< res1) {
    found = TRUE;
    conclurl = http_report_vuln_url(port: port, url: url1, url_only: TRUE);
  }

  if (res2 =~ "^HTTP/1\.[01] 200" && 'content="Pulse CMS' >< res2) {
    found = TRUE;
    conclurl += '\n' + http_report_vuln_url(port: port, url: url2, url_only: TRUE);
  }

  if (found) {
    version = "unknown";

    # content="Pulse CMS 5.3.7"
    vers = eregmatch(pattern: 'content="Pulse CMS ([0-9.]+)"', string: res2);
    if (!isnull(vers[1]))
      version = vers[1];

    set_kb_item(name: "pulsecms/detected", value: TRUE);
    set_kb_item(name: "pulsecms/http/detected", value: TRUE);

    cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:pulsecms:pulse_cms:");
    if (!cpe)
      cpe = "cpe:/a:pulsecms:pulse_cms";

    register_product(cpe: cpe, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Pulse CMS", version: version, install: install, cpe: cpe,
                                             concluded: vers[0], concludedUrl: conclurl),
                port: port);
    exit(0);
  }
}

exit(0);
