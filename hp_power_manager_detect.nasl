###############################################################################
# OpenVAS Vulnerability Test
#
# HP Power Manager Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100456");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2022-10-17T11:13:19+0000");
  script_tag(name:"last_modification", value:"2022-10-17 11:13:19 +0000 (Mon, 17 Oct 2022)");
  script_tag(name:"creation_date", value:"2010-01-20 19:30:24 +0100 (Wed, 20 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("HP Power Manager Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_goahead_detect.nasl");
  script_mandatory_keys("embedthis/goahead/detected");

  script_xref(name:"URL", value:"https://www.hpe.com/");

  script_tag(name:"summary", value:"This host is running HP Power Manager, an UPS management and monitoring
  utility.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

CPE = "cpe:/a:embedthis:goahead";

include("cpe.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if(!port = get_app_port(cpe: CPE))
  exit(0);

url = "/CPage/About_English.asp";

buf = http_get_cache(item:url, port:port);

if ("About HP Power Manager" >< buf) {
  vers = "unknown";

  version = eregmatch(string: buf, pattern: "HP Power Manager ([0-9.]+)[ ]*([(Build 0-9)]*)",icase:TRUE);
  if (!isnull(version[1])) {
    if ("Build" >< version[2]) {
      build = eregmatch(pattern: "\(Build ([0-9]+)\)", string: version[2]);
      vers = version[1] + "." + build[1];
    } else
      vers = version[1];
    concUrl = url;
  }

  set_kb_item(name: "hp_power_manager/detected", value: TRUE);

  cpe = build_cpe(value: vers, exp: "^([0-9.]+)", base: "cpe:/a:hp:power_manager:");
  if (!cpe)
    cpe = "cpe:/a:hp:power_manager";

  register_product(cpe: cpe, location: "/", port: port, service: "www");

  log_message(data: build_detection_report(app: "HP Power Manager", version: vers, install: "/", cpe: cpe,
                                           concluded: version[0], concludedUrl: concUrl),
              port: port);
  exit(0);
}

exit(0);
