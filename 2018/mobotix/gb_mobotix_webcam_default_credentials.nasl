###############################################################################
# OpenVAS Vulnerability Test
#
# Mobotix Webcam Default Credentials
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113233");
  script_version("2023-03-01T10:20:05+0000");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2018-07-19 10:04:40 +0200 (Thu, 19 Jul 2018)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("Mobotix Webcam Default Credentials (HTTP)");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Default Accounts");
  script_dependencies("gb_mobotix_webcam_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("mobotix/webcam/detected");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"summary", value:"The remote Mobotix Webcam is using known default credentials.");

  script_tag(name:"vuldetect", value:"Tries to login using default credentials.");

  script_tag(name:"insight", value:"It was possible to login with default credentials admin:meinsm.");

  script_tag(name:"affected", value:"All Mobotix Webcams.");

  script_tag(name:"solution", value:"Change the default password.");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

CPE = "cpe:/h:mobotix:webcam";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );
include( "misc_func.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! get_app_location( cpe: CPE, port: port, nofork: TRUE ) )
  exit( 0 );

username = "admin";
password = "meinsm";

auth_header = make_array( 'Authorization', 'Basic ' + base64( str: username + ":" + password ) );
req = http_get_req( port: port, url: "/", add_headers: auth_header );
buf = http_keepalive_send_recv( port: port, data: req );

if( 'Live <\\/TITLE>' >< buf ||
  ( 'params[\'size\']' >< buf && 'params[\'camera\']' >< buf && 'params[\'quality\']' >< buf ) ) {
  report = "It was possible to login using the username '" + username + "' and the password '" + password + "'.";
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
