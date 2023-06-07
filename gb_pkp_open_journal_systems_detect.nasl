###############################################################################
# OpenVAS Vulnerability Test
#
# PKP Open Journal Systems Detection
#
# Authors:
# Michael Martin <michael.martin@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.107321");
  script_version("2020-08-24T15:18:35+0000");
  script_tag(name:"last_modification", value:"2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2018-06-13 15:48:00 +0200 (Wed, 13 Jun 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("PKP Open Journal Systems Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of PKP Open Journal Systems.");

  script_xref(name:"URL", value:"https://pkp.sfu.ca/ojs/");

  exit(0);
}

include("cpe.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

port = http_get_port( default: 80 );

foreach dir( make_list_unique( "/", http_cgi_dirs( port: port ) ) ) {

  install = dir;
  if( dir == "/" ) dir = "";

  url = dir + "/";
  resp = http_get_cache( item: url, port: port );

  if( ( 'href="http://pkp.sfu.ca/ojs/"' >< resp || '<a href="https://pkp.sfu.ca/ojs/"' >< resp ) && '<meta name="generator" content="Open Journal Systems' >< resp ) {
    set_kb_item( name: "pkp/open_journal_systems/detected", value: TRUE );
    version = "unknown";

    version_match = eregmatch( pattern: '"Open Journal Systems ([0-9.-]+)"', string: resp );
    if( version_match[1] ) {
      version = version_match[1];
      set_kb_item( name:"pkp/open_journal_systems/version", value:version );
      concluded_url = http_report_vuln_url( port:port, url:url, url_only:TRUE );
    }

    register_and_report_cpe( app: "PKP Open Journal Systems", ver: version, concluded: version_match[0], base: "cpe:/a:pkp:open_journal_systems:", expr: '([0-9.-]+)', insloc: install, regService: "www", regPort: port, conclUrl: concluded_url );

    exit( 0 );
  }
}
