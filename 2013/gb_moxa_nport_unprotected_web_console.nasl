###############################################################################
# OpenVAS Vulnerability Test
#
# Moxa NPort Unprotected Web Console
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
  script_oid("1.3.6.1.4.1.25623.1.0.103664");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Moxa NPort Unprotected Web Console");

  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2013-02-19 12:01:48 +0100 (Tue, 19 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("MoxaHttp/banner");

  script_tag(name:"solution", value:"Set a password.");
  script_tag(name:"solution_type", value:"Workaround");

  script_tag(name:"summary", value:"The remote Moxa NPort Web Console is not protected by a password.");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");

port = http_get_port(default:80);

banner = http_get_remote_headers(port:port);
if(!banner || "Server: MoxaHttp/1.0" >!< banner)exit(0);

url = '/main.htm';

if(http_vuln_check(port:port, url:url,pattern:"Basic Settings",extra_check:make_list("Model Name","MAC Address"))) {

  security_message(port:port);
  exit(0);

}

exit(0);

