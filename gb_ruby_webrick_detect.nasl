# Copyright (C) 2020 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112709");
  script_version("2021-05-14T13:11:51+0000");
  script_tag(name:"last_modification", value:"2021-05-14 13:11:51 +0000 (Fri, 14 May 2021)");
  script_tag(name:"creation_date", value:"2020-03-11 10:49:11 +0000 (Wed, 11 Mar 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("WEBrick Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("WEBrick/banner");

  script_tag(name:"summary", value:"HTTP based detection of WEBrick.

  In addition this script also tries to detect Ruby itself.");

  script_xref(name:"URL", value:"https://github.com/ruby/webrick");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");

port = http_get_port( default: 3000 );

buf = http_get_remote_headers( port: port );

if( concl = egrep( string:buf, pattern:"^Server\s*:.*WEBrick", icase:TRUE ) ) {
  concl = chomp( concl );
  set_kb_item( name: "ruby-lang/webrick/detected", value: TRUE );
  set_kb_item( name: "ruby-lang/ruby/detected", value: TRUE );

  version = "unknown";

  # Server: WEBrick/1.3.1
  # Server: WEBrick/1.3.1 (Ruby/1.8.7/2013-06-27) OpenSSL/1.0.1e
  # Server: WEBrick/1.3.1 (Ruby/2.0.0/2014-05-08)
  match = eregmatch( string: buf, pattern: "Server\s*:.*WEBrick/([0-9.]+)(\s*\(Ruby/([0-9.]+))?", icase: TRUE );
  if( ! isnull( match[1] ) )
    version = match[1];

  register_and_report_cpe( app: "WEBrick",
                           ver: version,
                           concluded: concl,
                           base: "cpe:/a:ruby-lang:webrick:",
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );

  if( ! isnull( match[3] ) ) {
    set_kb_item( name: "ruby/detected", value: TRUE );
    set_kb_item( name: "ruby/http/detected", value: TRUE );
    set_kb_item( name: "ruby/http/port", value: port );
    set_kb_item( name: "ruby/http/" + port + "/concluded", value: concl );
    set_kb_item( name: "ruby/http/" + port + "/version", value: match[3] );
    set_kb_item( name: "ruby/http/" + port + "/location", value: port + "/tcp" );
    set_kb_item( name: "ruby/http/" + port + "/install", value: port + "#---#" + port + "/tcp#---#" + match[3] + "#---#" + match[0] );
  }
}

exit( 0 );
