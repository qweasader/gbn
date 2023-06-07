###############################################################################
# OpenVAS Vulnerability Test
#
# ExaGrid Default HTTP Login
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105598");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("ExaGrid Default Credentials (HTTP)");

  script_tag(name:"impact", value:"Attackers can exploit this issue to obtain sensitive information that may lead to further attacks.");

  script_tag(name:"vuldetect", value:"Try to login with default credentials 'support:support'.");

  script_tag(name:"solution", value:"Update to 4.8 P26 or later");

  script_tag(name:"summary", value:"The remote ExaGrid device has default credentials set.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2016-04-07 17:41:14 +0200 (Thu, 07 Apr 2016)");
  script_category(ACT_ATTACK);
  script_family("Default Accounts");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("ExaGrid/banner");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("misc_func.inc");

port = http_get_port( default:80 );
banner = http_get_remote_headers( port:port );

if( ! banner || "Server: ExaGrid" >!< banner )
  exit( 0 );

user = "support";
pass = "support";

userpass = user + ":" + pass;
userpass64 = base64( str:userpass );

post_data = '<?xml version="1.0"?>
<IsysMessage>
   <header>
      <p2pVersion major="1" minor="0"/>
      <messageVersion major="1" minor="0"/>
   </header>
   <body>
      <action>ListAssets</action>
      <status>0</status>
      <parameters>
      </parameters>
   </body>
</IsysMessage>';

len = strlen( post_data );
useragent = http_get_user_agent();
host = http_host_name( port:port );

req = 'POST /init HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n' +
      'Accept-Language: en-US,en;q=0.5\r\n' +
      'Accept-Encoding: identify\r\n' +
      'Content-Type: text/plain; charset=UTF-8\r\n' +
      'Content-Length: ' + len + '\r\n' +
      'Cookie: tree_GridTree_state=7\r\n' +
      'Authorization: Basic ' + userpass64 + '\r\n' +
      'Connection: close\r\n' +
      '\r\n' +
      post_data;
res = http_keepalive_send_recv( port:port, data:req );

if( res =~ "^HTTP/1\.[01] 200" && "listAssetsResponse" >< res && "Repository name" >< res ) {
  report = 'It was possible to login into the remote ExaGrid device using username `support` and password `support`.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 0 );
