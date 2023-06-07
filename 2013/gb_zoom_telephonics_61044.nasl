###############################################################################
# OpenVAS Vulnerability Test
#
# Multiple Zoom Telephonics Devices Multiple Security Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2013 Greenbone Networks GmbH
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
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103756");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_version("2022-04-25T14:50:49+0000");

  script_name("Multiple Zoom Telephonics Devices Multiple Security Vulnerabilities");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61044");

  script_tag(name:"last_modification", value:"2022-04-25 14:50:49 +0000 (Mon, 25 Apr 2022)");
  script_tag(name:"creation_date", value:"2013-08-12 15:24:34 +0200 (Mon, 12 Aug 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("Nucleus/banner");

  script_tag(name:"impact", value:"Exploiting these issues could allow an attacker to gain unauthorized
  access and perform arbitrary actions, obtain sensitive information, compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"vuldetect", value:"Request /hag/pages/toolbox.htm and check if it is accessible without authentication.");

  script_tag(name:"insight", value:"When UPnP services and WAN http administrative access are enabled,
  authorization and credential challenges can be bypassed by directly
  accessing root privileged abilities via a web browser URL.

  All aspects of the modem/router can be changed, altered and controlled
  by an attacker, including gaining access to and changing the PPPoe/PPP ISP credentials.");

  script_tag(name:"solution", value:"Ask the Vendor for an update.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Multiple Zoom Telephonics devices are prone to an information-
  disclosure vulnerability, an authentication bypass vulnerability and an SQL-injection vulnerability.");

  script_tag(name:"affected", value:"X4 ADSL Modem and Router

  X5 ADSL Modem and 4-port Router");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if("401 Unauthorized" >!< banner || "Server: Nucleus/" >!< banner)exit(0);

if(http_vuln_check(port:port, url:'/hag/pages/toolbox.htm',pattern:"<title>Advanced Setup", extra_check:make_list("WAN Configuration","ADSL Status"))) {
  security_message(port:port);
  exit(0);
}

exit(0);
