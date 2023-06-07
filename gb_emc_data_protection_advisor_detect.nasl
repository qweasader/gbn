###############################################################################
# OpenVAS Vulnerability Test
#
# EMC Data Protection Advisor Detection
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.106548");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2017-01-30 10:52:02 +0700 (Mon, 30 Jan 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Dell EMC Data Protection Advisor Detection");

  script_tag(name:"summary", value:"Detection of Dell EMC Data Protection Advisor

  The script sends a HTTP connection request to the server and attempts to detect the presence of Dell EMC Data
  Protection Advisor and to extract its version.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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
