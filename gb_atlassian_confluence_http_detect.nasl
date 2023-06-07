# Copyright (C) 2011 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103152");
  script_version("2022-03-08T10:46:23+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-08 10:46:23 +0000 (Tue, 08 Mar 2022)");
  script_tag(name:"creation_date", value:"2011-05-02 15:13:22 +0200 (Mon, 02 May 2011)");
  script_name("Atlassian Confluence Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Atlassian Confluence.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default: 80);

foreach dir(make_list_unique("/", "/confluence", "/wiki", http_cgi_dirs(port: port))) {

  install = dir;
  if(dir == "/")
    dir = "";

  url = dir + "/login.action";
  buf = http_get_cache(item: url, port: port);
  if(!buf)
    continue;

  found = 0;
  concluded = ""; # nb: Overwrite a possible previous set string

  if(concl = egrep(pattern: "Powered by <a[^>]+>Atlassian Confluence", string: buf, icase: TRUE)) {

    found++;

    # nb: Minor formatting change for the reporting.
    concl = chomp(concl);
    concl = ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
    concluded += "  " + concl;
  }

  if(concl = egrep(pattern: '<form.*name="loginform" method="POST" action="[^"]*/dologin.action"', string: buf, icase: TRUE)) {

    found++;

    if(concluded)
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp(concl);
    concl = ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
    concluded += "  " + concl;
  }

  # The default:
  # <title>Log In - Confluence</title>
  # but also seen other variants:
  # <title>Log In - $somename Confluence</title>
  # <title>Log In - $somename-Confluence</title>
  # <title>Log In - $somename Confluence $someadditionalstring</title>
  if(concl = egrep(pattern: "^\s*<title>Log In - [^<]*Confluence[^<]*</title>", string: buf, icase: FALSE)) {

    # nb: Counts twice (as done in the initial version of the detection)
    found += 2;

    if(concluded)
      concluded += '\n';

    # nb: Minor formatting change for the reporting.
    concl = chomp(concl);
    concl = ereg_replace(string: concl, pattern: "^(\s+)", replace: "");
    concluded += "  " + concl;
  }

  if(found > 1) {

    version = "unknown";
    extra = "";
    conclUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

    # >Atlassian Confluence</a> <span id='footer-build-information'>7.13.2</span>
    # <meta name="ajs-version-number" content="7.13.2">
    if(!vers = eregmatch(string: buf, pattern: "Atlassian Confluence</a>.+>([0-9.]+)", icase: TRUE))
      vers = eregmatch(string: buf, pattern: '<meta name="ajs-version-number" content="([0-9.]+)">', icase: TRUE);

    if(vers[1]) {
      version = vers[1];
      concluded += '\n  ' + vers[0];
    }

    # <meta name="ajs-build-number" content="8703">
    build_info = eregmatch(pattern: '<meta name="ajs-build-number" content="([0-9]+)">', string: buf, icase: TRUE);
    if(build_info[1]) {
      extra += "Build: " + build_info[1];
      concluded += '\n  ' + build_info[0];
    }

    if(version == "unknown") {
      # nb: Product information also exists on an unauthenticated REST endpoint
      url = dir + "/rest/applinks/1.0/manifest";
      req = http_get(item: url, port: port);
      buf = http_keepalive_send_recv(port: port, data: req, bodyonly: TRUE);

      vers = eregmatch(string: buf, pattern: "<version>([0-9.]+)</version>", icase: TRUE);
      if(vers[1]) {
        version = vers[1];
        concluded += '\n  ' + vers[0];
        conclUrl += '\n' + http_report_vuln_url(port: port, url: url, url_only: TRUE);

        # nb: not the Confluence build but its marketplace builder number, according to:
        # https://developer.atlassian.com/server/confluence/confluence-build-information/
        mp_build_info = eregmatch(pattern: "<buildNumber>([0-9]+)", string: buf, icase: TRUE);
        if(mp_build_info[1]) {
          extra += '\nMarketplace Build: ' + mp_build_info[1];
          concluded += '\n  ' + mp_build_info[0];
        }
      }
    }

    set_kb_item(name: "atlassian/confluence/detected", value: TRUE);
    set_kb_item(name: "atlassian/confluence/http/detected", value: TRUE);

    cpe1 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:confluence:");
    cpe2 = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:atlassian:confluence_server:");
    if(!cpe1) {
      cpe1 = "cpe:/a:atlassian:confluence";
      cpe2 = "cpe:/a:atlassian:confluence_server";
    }

    register_product(cpe: cpe1, location: install, port: port, service: "www");
    register_product(cpe: cpe2, location: install, port: port, service: "www");

    log_message(data: build_detection_report(app: "Atlassian Confluence",
                                             version: version,
                                             install: install,
                                             cpe: cpe1,
                                             concluded: concluded,
                                             concludedUrl: conclUrl,
                                             extra: extra),
                                             port: port);

    exit(0);
  }
}

exit(0);
