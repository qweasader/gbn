###############################################################################
# OpenVAS Vulnerability Test
#
# Shareaza Detection (HTTP)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800603");
  script_version("2020-12-23T12:06:42+0000");
  script_tag(name:"last_modification", value:"2020-12-23 12:06:42 +0000 (Wed, 23 Dec 2020)");
  script_tag(name:"creation_date", value:"2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Shareaza Detection (HTTP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 6346);
  script_mandatory_keys("Shareaza/banner");

  script_tag(name:"summary", value:"HTTP based detection of Shareaza.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("host_details.inc");

port = http_get_port(default:6346);
if(!banner = http_get_remote_headers(port:port))
  exit( 0 );

if(!concluded = egrep(string:banner, pattern:"^Server\s*:\s*Shareaza", icase:TRUE))
  exit(0);

concluded = chomp(concluded);
version = "unknown";
install = port + "/tcp";

# Server: Shareaza 2.7.9.0
# Server: Shareaza 2.3.1.0
vers = eregmatch(pattern:"Server\s*:\s*Shareaza ([0-9.]+)", string:banner, icase:TRUE);
if(vers[1]) {
  version = vers[1];
  concluded = vers[0];
}

set_kb_item(name:"shareaza/detected", value:TRUE);
set_kb_item(name:"www/" + port + "/Shareaza", value:version);

register_and_report_cpe(app:"Shareaza",
                        ver:version,
                        concluded:concluded,
                        base:"cpe:/a:ryo-oh-ki:shareaza:",
                        expr:"([0-9.]+)",
                        insloc:install,
                        regPort:port,
                        regService:"www");

exit(0);
