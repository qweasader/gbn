# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.113557");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-11-08 15:48:22 +0200 (Fri, 08 Nov 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Forcepoint Email Security Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Checks whether Forcepoint Email Security
  is present on the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://www.forcepoint.com/product/email-security");

  exit(0);
}

CPE = "cpe:/a:forcepoint:email_security:";

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");
include("cpe.inc");

port = http_get_port( default: 443 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {
  location = dir;
  if( location == "/" )
    location = "";

  url = location + "/pem/login/pages/login.jsf";

  buf = http_get_cache( port: port, item: url );
  if( buf =~ "^HTTP/1\.[01] 200" && buf =~ '<title>Forcepoint Email Security' ) {
    set_kb_item( name: "forcepoint/email_security/detected", value: TRUE );

    version = "unknown";

    ver = eregmatch( string: buf, pattern: '&nbsp;Version&nbsp;([0-9.]+)' );
    if( ! isnull( ver[1] ) )
      version = ver[1];

    register_and_report_cpe( app: "Forcepoint Email Security",
                             ver: version,
                             concluded: ver[0],
                             base: CPE,
                             expr: '([0-9.]+)',
                             insloc: dir,
                             regPort: port,
                             regService: "www",
                             conclUrl: url );
  }
}

exit( 0 );
