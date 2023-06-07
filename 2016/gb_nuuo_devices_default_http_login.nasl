###############################################################################
# OpenVAS Vulnerability Test
#
# NUUO Network Video Recorder Default Credentials
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:nuuo:nuuo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105856");
  script_version("2023-03-01T10:20:04+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("NUUO Network Video Recorder Default Credentials (HTTP)");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:04 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2016-08-08 19:16:36 +0200 (Mon, 08 Aug 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_nuuo_devices_web_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80, 443);
  script_mandatory_keys("nuuo/web/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote NUUO Network Video Recorder web interface is using known default credentials.");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain access
  to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials: admin/admin");

  script_tag(name:"solution", value:"Change the password.");

  script_tag(name:"solution_type", value:"Workaround");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port, nofork:TRUE ) )
  exit( 0 );

if( ! cookie = get_kb_item( "nuuo/web/cookie" ) )
  exit( 0 );

login_data = 'language=en&user=admin&pass=admin&browser_engine=firefox';

req = http_post_put_req( port:port,
                     url:'/login.php',
                     data:login_data,
                     accept_header:'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                     add_headers: make_array("Cookie", cookie + '; loginName=admin',
                                             "Content-Type", "application/x-www-form-urlencoded") );

buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "cmd=loginfail" >< buf ) exit( 99 );

if( http_vuln_check( port:port,
                     url:"/save_config.php",
                     pattern:'<title>Save Configuration</title>',
                     check_header:TRUE,
                     cookie:cookie + '; loginName=admin' ) )
{
  report = 'It was possible to login into the remote NUUO Network Video Recorder web interface using `admin` as username and password.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

