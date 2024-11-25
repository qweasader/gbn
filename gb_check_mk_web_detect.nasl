# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140097");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2024-06-20T05:05:33+0000");
  script_tag(name:"last_modification", value:"2024-06-20 05:05:33 +0000 (Thu, 20 Jun 2024)");
  script_tag(name:"creation_date", value:"2016-12-12 13:59:50 +0100 (Mon, 12 Dec 2016)");
  script_name("Checkmk / Check_MK Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl",
                      "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://checkmk.com");

  script_tag(name:"summary", value:"HTTP based detection of Checkmk (formerly Check_MK).");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

detection_patterns = make_list(
  # <title>Check_MK Multisite Login</title>
  # <title>Check_MK</title>
  # <title>Checkmk $somestring</title>
  "<title>Check(_MK|mk)[^<]*<",

  # <a href="https://mathias-kettner.com">Mathias Kettner</a>
  ">Mathias Kettner<",
  '<a href="https?://mathias-kettner\\.com',

  # <a href="https://checkmk.com" target="_blank">Checkmk GmbH</a>
  # <a href="https://checkmk.com" target="_blank">tribe29 GmbH</a>
  ">(Checkmk|tribe29) GmbH<",
  '<a href="https?://checkmk\\.com',

  # <script>cmk.visibility_detection.initialize();</script>
  #
  # but also on a separate line like e.g.:
  #
  # <script type="text/javascript">
  # cmk.visibility_detection.initialize();
  #
  "cmk\.visibility_detection\.initialize\(\);",

  "checkmk_logo\.svg",
  "check_mk\.css");

foreach dir (make_list_unique("/", "/monitor", "/cmk", "/check_mk", "/checkmk", http_cgi_dirs(port:port))) {

  install = dir;
  if (dir == "/")
    dir = "";

  foreach subdir (make_list("", "/check_mk")) {

    url = dir + subdir + "/login.py";

    # nb: No need to check this as it is most likely duplicated
    if ("/check_mk/check_mk" >< url)
      continue;

    buf = http_get_cache(item:url, port:port);
    if (!buf || buf !~ "^HTTP/1\.[01] 200")
      continue;

    found = 0;
    concluded = "";

    foreach pattern (detection_patterns) {

      concl = eregmatch(string:buf, pattern:pattern, icase:TRUE);
      if (concl[0]) {
        found++;
        if (concluded)
          concluded += '\n';
        concluded += "  " + concl[0];
      }
    }

    if (found > 1) {

      cpe = "cpe:/a:check_mk_project:check_mk";
      version = "unknown";
      conclUrl = "  " + http_report_vuln_url(port:port, url:url, url_only:TRUE);

      set_kb_item(name:"check_mk/detected", value:TRUE);
      set_kb_item(name:"check_mk/http/detected", value:TRUE);

      # </div><div id="foot">Version: 2.3.0p3 - &copy; <a href="https://checkmk.com" target="_blank">Checkmk GmbH</a>
      # </div><div id="foot">Version: 1.6.0p22 - &copy; <a href="https://checkmk.com" target="_blank">tribe29 GmbH</a>
      # </div><div id="foot">Version: 1.5.0p5 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      # </div><div id="foot">Version: 1.5.0p11 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      # </div><div id="foot">Version: 1.4.0p23 - &copy; <a href="https://mathias-kettner.com">Mathias Kettner</a>
      vers = eregmatch(pattern:">Version\s*:\s*([0-9.]+(p[0-9]+)?)", string:buf);
      if (!isnull(vers[1])) {
        version = vers[1];
        cpe += ":" + version;
        concluded += '\n  ' + vers[0];
      }

      register_product(cpe:cpe, location:install, port:port, service:"www");

      log_message(data:build_detection_report(app:"Checkmk / Check_MK",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concludedUrl:conclUrl,
                                              concluded:concluded),
                  port:port);

      exit(0); # nb: Should be usually only installed once...
    }
  }
}

exit(0);
