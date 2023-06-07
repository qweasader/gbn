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
  script_oid("1.3.6.1.4.1.25623.1.0.113343");
  script_version("2023-01-27T10:09:24+0000");
  script_tag(name:"last_modification", value:"2023-01-27 10:09:24 +0000 (Fri, 27 Jan 2023)");
  script_tag(name:"creation_date", value:"2019-02-26 12:57:55 +0100 (Tue, 26 Feb 2019)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-9126");

  script_name("D-Link DIR-825 Information Disclosure Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dlink_dir_consolidation.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("d-link/dir/http/detected", "d-link/dir/model");

  script_tag(name:"summary", value:"D-Link DIR-825 devices are prone to an information disclosure
  vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to access sensitive information.");

  script_tag(name:"insight", value:"The vulnerability exists due to a logical problem while handling
  permissions in the function do_widget_action.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to access sensitive
  information, including, but not limited to, the WPS Pin, SSID, MAC address, and routing table.");

  script_tag(name:"affected", value:"D-Link DIR-825 devices through firmware version 2.10B1.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since
  the disclosure of this vulnerability. Likely none will be provided anymore. General solution options
  are to upgrade to a newer release, disable respective features, remove the product or replace the
  product by another one.");

  exit(0);
}

CPE = "cpe:/h:d-link:dir-825";

include( "host_details.inc" );
include( "http_func.inc" );
include( "http_keepalive.inc" );

if( ! port = get_app_port( cpe: CPE ) )
  exit( 0 );

if( ! location = get_app_location( cpe: CPE, port: port ) )
  exit( 0 );

if( location == "/" )
  location = "";

url = location + "/router_info.xml?section=wps";

buf = http_get_cache( item: url, port: port );

if( buf !~ 'Illegal File access' && buf =~ '<pin>[0-9]+</pin>' ) {
  report = http_report_vuln_url( port: port, url: url );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
