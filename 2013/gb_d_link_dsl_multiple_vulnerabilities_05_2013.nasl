###############################################################################
# OpenVAS Vulnerability Test
#
# D-Link DSL-320B Multiple Security Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103706");
  script_version("2020-08-24T15:18:35+0000");

  script_name("D-Link DSL-320B Multiple Security Vulnerabilities");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");

  script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-018");
  script_xref(name:"URL", value:"http://www.dlink.com/de/de/home-solutions/connect/modems-and-gateways/dsl-320b-adsl-2-ethernet-modem");
  script_xref(name:"URL", value:"http://www.dlink.com/");

  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-05-06 12:58:41 +0200 (Mon, 06 May 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("micro_httpd/banner");

  script_tag(name:"solution", value:"Firmware update is available.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"D-Link DSL-320B is prone to the following security
  vulnerabilities:

  1. Access to the Config file without authentication

  2. Access to the logfile without authentication

  3. Stored XSS within parental control");

  script_tag(name:"impact", value:"An attacker can exploit these issues to gain access to
  potentially sensitive information, decrypt stored passwords, steal cookie-based
  authentication credentials.");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(banner && "Server: micro_httpd" >!< banner)exit(0);

if(http_vuln_check(port:port, url:"/",pattern:"DSL-")) {

  if(http_vuln_check(port:port, url:"/config.bin",pattern:"sysPassword",extra_check:"sysUserName")) {
    report = http_report_vuln_url( port:port, url:'/config.bin' );
    security_message(port:port, data:report);
    exit(0);
  }

  exit(99);

}

exit(0);

