# Copyright (C) 2018 Greenbone Networks GmbH
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113158");
  script_version("2022-03-28T10:48:38+0000");
  script_tag(name:"last_modification", value:"2022-03-28 10:48:38 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"creation_date", value:"2018-04-17 15:50:00 +0200 (Tue, 17 Apr 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("IkiWiki Detection Consolidation");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_ikiwiki_ssh_detect.nasl", "gb_ikiwiki_webui_detect.nasl");
  script_mandatory_keys("ikiwiki/detected");

  script_tag(name:"summary", value:"Consolidation of IkiWiki detections.");

  script_xref(name:"URL", value:"https://ikiwiki.info/");

  exit(0);
}

CPE = "cpe:/a:ikiwiki:ikiwiki";

include( "host_details.inc" );
include( "cpe.inc" );

version_array = make_array( );

# Due to possibility of multiple, varying versions, the versions are collected in the format
# "[version]" : "[port]:[location]:[concluded]"

if( webui_ports = get_kb_list( "ikiwiki/webui/port" ) ) {
  foreach port( webui_ports ) {
    concluded = get_kb_item( "ikiwiki/webui/" + port + "/concluded" );
    location = get_kb_item( "ikiwiki/webui/" + port + "/location" );
    version = get_kb_item( "ikiwiki/webui/" + port + "/version" );
    register_product( cpe: CPE, location: location, port: port, service: "www" );
    if( isnull( version_array[version] ) ) {
      version_array[version] = port + ":" + location + ":" + concluded;
    }
  }
}

if( ssh_ports = get_kb_list( "ikiwiki/ssh/port" ) ) {
  foreach port( ssh_ports ) {
    concluded = get_kb_item( "ikiwiki/ssh/" + port + "/concluded" );
    location = get_kb_item( "ikiwiki/ssh/" + port + "/location" );
    version = get_kb_item( "ikiwiki/ssh/" + port + "/version" );
    register_product( cpe: CPE, location: location, port: port );
    if( isnull(version_array[version] ) ) {
      version_array[version] = port + ":" + location + ":" + concluded;
    }
  }
}

foreach version ( keys( version_array ) ) {
  infos = eregmatch( string: version_array[version], pattern: "([^:]*):([^:]*):([^:]*)" );
  if( ! isnull( infos[1] ) ) port = infos[1];
  if( ! isnull( infos[2] ) ) location = infos[2];
  if( ! isnull( infos[3] ) ) concluded = infos[3];

  register_and_report_cpe( app: "IkiWiki",
                           ver: version,
                           base: CPE + ":",
                           expr: "([0-9.]+)",
                           regPort: port,
                           insloc: location,
                           concluded: concluded
                         );
}

exit( 0 );
