# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900945");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2009-09-22 10:03:41 +0200 (Tue, 22 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("GeoServer Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 8080);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of GeoServer.");

  script_xref(name:"URL", value:"https://geoserver.org/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 8080);

foreach dir (make_list_unique("/", "/geoserver", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage";

  res = http_get_cache(port: port, item: url);

  if (res =~ "^HTTP/1\.[01] 302") {
    # nb: Need to check both variants as it *might* depend on the server configuration
    current_dirs = make_list(install, dir + "/web/wicket/bookmarkable");
    foreach current_dir (current_dirs) {
      loc = http_extract_location_from_redirect(port: port, data: res, current_dir: current_dir);
      if (loc) {
        url = loc;
        res2 = http_get_cache(port: port, item: loc);
        if (res2 && res2 =~ "^HTTP/1\.[01] 200") {
          res = res2;
          break;
        }
      }
    }
  }

  if ("<title>GeoServer: About GeoServer" >!< res) {
    url = dir + "/web/?wicket:bookmarkablePage=:org.geoserver.web.AboutGeoServerPage";

    res = http_get_cache(port: port, item: url);

    if ("<title>GeoServer: About GeoServer" >!< res) {
      url = dir + "/welcome.do";

      res = http_get_cache(port: port, item: url);

      if ("My GeoServer" >!< res || "Welcome to GeoServer" >!< res)
        continue;
    }
  }

  version = "unknown";

  # <label for="version">GeoServer Version</label>
  # <span id="version">2.17.2</span>
  #
  # Versions might have RC or beta releases (e.g. 2.0.1-RC1 or 2.0.1-beta1)
  vers = eregmatch(pattern: 'id="version">([^<]+)<', string: res);
  if (isnull(vers[1])) {
    # Welcome to GeoServer 1.7.0
    vers = eregmatch(pattern: "Welcome to GeoServer ([0-9.]+(-[a-zA-Z]+[0-9]+)?)", string: res);
  }

  if (!isnull(vers[1])) {
    version = vers[1];
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "geoserver/detected", value: TRUE);
  set_kb_item(name: "geoserver/http/detected", value: TRUE);

  cpe = build_cpe(value: tolower(version), exp: "^([0-9.]+)-?([a-zA-Z0-9]+)?", base: "cpe:/a:geoserver:geoserver:");
  if (!cpe)
    cpe = "cpe:/a:geoserver:geoserver";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "GeoServer", version: version, install: install,
                                           cpe: cpe, concluded: vers[0], concludedUrl: concUrl),
              port: port);

  exit(0);
}

exit(0);
