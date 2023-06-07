###############################################################################
# OpenVAS Vulnerability Test
#
# inGate SIParator Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103206");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("2020-11-12T09:36:23+0000");
  script_tag(name:"last_modification", value:"2020-11-12 09:36:23 +0000 (Thu, 12 Nov 2020)");
  script_tag(name:"creation_date", value:"2011-08-17 15:40:19 +0200 (Wed, 17 Aug 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("inGate SIParator Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("Ingate-SIParator/banner");
  script_require_ports("Services/www", 80);

  script_tag(name:"summary", value:"This host is an inGate SIParator, a device that connects to an
  existing network firewall to seamlessly enable SIP Communications.");

  script_xref(name:"URL", value:"http://www.ingate.com/Products_siparators.php");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port: port);

if(!banner || "erver: Ingate-SIParator" >!< banner)exit(0);

vers = "unknown";
version = eregmatch(pattern:"Server: Ingate-SIParator/([0-9.]+)", string:banner);

if(!isnull(version[1]))vers = version[1];

set_kb_item(name:string(port,"/Ingate_SIParator"),value:vers);
set_kb_item(name:"ingate_siparator/detected", value:TRUE);

if(vers == "unknown") {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:siparator"));
} else {
  register_host_detail(name:"App", value:string("cpe:/h:ingate:siparator:",vers));
}

report = string("inGate SIParator version '",vers,"' was detected.\n");

log_message(port:port,data:report);

exit(0);

