# Copyright (C) 2009 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100001");
  script_version("2021-07-22T08:27:04+0000");
  script_tag(name:"last_modification", value:"2021-07-22 08:27:04 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"creation_date", value:"2009-02-26 04:52:45 +0100 (Thu, 26 Feb 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("osCommerce Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of osCommerce.");

  script_xref(name:"URL", value:"https://www.oscommerce.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("list_array_func.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

if (!http_can_host_php(port: port))
  exit(0);

foreach dir (make_list_unique("/", "/osc", "/oscommerce", "/store", "/catalog", "/shop", http_cgi_dirs(port: port))) {
  install = dir;
  if (dir == "/")
    dir = "";

  url = dir + "/index.php";
  res = http_get_cache(item: url, port: port);
  if (!res)
    continue;

  if (res !~ "^HTTP/1\.[01] 200" || ("osCsid=" >!< res && !egrep(string: res, pattern: "Powered by.+osCommerce", icase: FALSE))) {
    url = dir + "/ssl_check.php";
    res = http_get_cache(item: url, port: port);
    # In English:
    # We validate the SSL Session ID automatically generated
    # *snip*
    # We have detected that your browser has generated a different SSL Session ID
    #
    # or in German:
    # Die von Ihrem Browser erzeugte SSL-Session ID
    # *snip*
    # Unsere Sicherheits&uuml;berpr&uuml;fung hat ergeben, dass der Ihrerseits verwendete Browser die SSL-Session-Id
    if (res !~ "^HTTP/1\.[01] 200" || !eregmatch(string: res, pattern: "SSL.+I[Dd].+SSL.+I[Dd]", icase: FALSE))
      continue;
  }

  version = "unknown";

  set_kb_item(name: "oscommerce/detected", value: TRUE);
  set_kb_item(name: "oscommerce/http/detected", value: TRUE);

  concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);

  cpe = "cpe:/a:oscommerce:oscommerce";

  register_product(cpe: cpe, location: install, port: port, service: "www");

  log_message(data: build_detection_report(app: "osCommerce", version: version, install: install,
                                           cpe: cpe, concludedUrl: concUrl),
              port: port);
}

exit(0);
