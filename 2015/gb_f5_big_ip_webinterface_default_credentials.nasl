# Copyright (C) 2015 Greenbone Networks GmbH
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

CPE = "cpe:/h:f5:big-ip";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105163");
  script_version("2022-05-09T11:19:09+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-05-09 11:19:09 +0000 (Mon, 09 May 2022)");
  script_tag(name:"creation_date", value:"2015-01-09 16:30:36 +0100 (Fri, 09 Jan 2015)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("F5 Networks BIG-IP Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_family("Default Accounts");
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_f5_big_ip_http_detect.nasl", "gb_default_credentials_options.nasl");
  script_mandatory_keys("f5/big_ip/http/detected");
  script_require_ports("Services/www", 443);
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote F5 BIG-IP device is using known default credentials
  for the HTTP login.");

  script_tag(name:"vuldetect", value:"Tries to login via HTTP using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or to modify system configuration.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin");

  script_tag(name:"solution", value:"Change the password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

pd = "username=admin&passwd=admin";

req = http_post( port:port, item:"/tmui/logmein.html", data:pd );
res = http_keepalive_send_recv( port:port, data:req );

if( "BIGIPAuthCookie" >< res && "BIGIPAuthUsernameCookie" >< res ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );
