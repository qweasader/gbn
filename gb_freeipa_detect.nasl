###############################################################################
# OpenVAS Vulnerability Test
#
# freeIPA Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140334");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-08-30 08:37:15 +0700 (Wed, 30 Aug 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("FreeIPA Detection");

  script_tag(name:"summary", value:"Detection of FreeIPA.

  The script sends a connection request to the server and attempts to detect FreeIPA and to extract its version.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.freeipa.org");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default: 443);

res = http_get_cache(port: port, item: "/ipa/ui/");

if ("<title>IPA: Identity Policy Audit</title>" >< res && "freeipa/app" >< res) {
  version = "unknown";

  url = "/ipa/ui/js/libs/loader.js";
  req = http_get(port: port, item: url);
  res = http_keepalive_send_recv(port: port, data: req);

  # num_version: '40404' for version 4.4.4
  vers = eregmatch(pattern: "num_version: '([0-9]+)", string: res);
  if (!isnull(vers[1])) {
    version = vers[1];
    if (strlen(version) == 5) {
      v1 = version[0];
      v2 = ereg_replace(string: substr(version, 1, 2), pattern: "^0", replace: "");
      v3 = ereg_replace(string: substr(version, 3, 4), pattern: "^0", replace: "");
      version = v1 + "." + v2 + "." + v3;
    }
    concUrl = http_report_vuln_url(port: port, url: url, url_only: TRUE);
  }

  set_kb_item(name: "freeipa/detected", value: TRUE);

  cpe = build_cpe(value: version, exp: "^([0-9.]+)", base: "cpe:/a:freeipa:freeipa:");
  if (!cpe)
    cpe = 'cpe:/a:freeipa:freeipa';

  register_product(cpe: cpe, location: "/ipa", port: port, service: "www");

  log_message(data: build_detection_report(app: "FreeIPA", version: version, install: "/ipa", cpe: cpe,
                                           concluded: vers[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
