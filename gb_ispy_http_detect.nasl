# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170268");
  script_version("2023-02-28T10:20:42+0000");
  script_tag(name:"last_modification", value:"2023-02-28 10:20:42 +0000 (Tue, 28 Feb 2023)");
  script_tag(name:"creation_date", value:"2022-12-06 13:25:16 +0000 (Tue, 06 Dec 2022)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("iSpyConnect iSpy Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("iSpy/banner");

  script_tag(name:"summary", value:"HTTP based detection of iSpyConnect iSpy.");

  script_xref(name:"URL", value:"https://www.ispyconnect.com/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("os_func.inc");
include("port_service_func.inc");

port = http_get_port( default:8080 );

url = "/";

res = http_get_cache( port:port, item:url );

if( concl = egrep( string:res, pattern:"(iSpy is running\. Access this server via the website|^[Ss]erver\s*:\s*iSpy)", icase:FALSE ) ) {

  set_kb_item( name:"ispyconnect/ispy/detected", value:TRUE );
  set_kb_item( name:"ispyconnect/ispy/http/detected", value:TRUE );

  concluded = chomp( concl );
  version = "unknown";
  install = port + "/tcp";

  cpe = "cpe:/a:ispyconnect:ispy";

  os_register_and_report( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", port:port, runs_key:"windows",
                          desc:"iSpyConnect iSpy Detection (HTTP)" );

  register_product( cpe:cpe, location:install, port:port, service:"www" );

  log_message( data:build_detection_report( app:"iSpyConnect iSpy", version:version, install:install, cpe:cpe, concluded:concluded ),
               port:port );
}

exit( 0 );
