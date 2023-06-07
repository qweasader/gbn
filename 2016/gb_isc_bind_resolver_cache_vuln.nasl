##############################################################################
# OpenVAS Vulnerability Test
#
# ISC BIND Resolver Cache Vulnerability (Jan 2016)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:isc:bind";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807217");
  script_version("2022-04-13T13:17:10+0000");
  script_cve_id("CVE-2012-1033");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2022-04-13 13:17:10 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2016-01-28 12:39:11 +0530 (Thu, 28 Jan 2016)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_name("ISC BIND Resolver Cache Vulnerability (Jan 2016)");

  script_tag(name:"summary", value:"ISC BIND is prone to a resolver cache vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the resolver
  overwrites cached server names and TTL values in NS records during the
  processing of a response to an A record query.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to trigger continued resolvability of domain names that are no
  longer registered.");

  script_tag(name:"affected", value:"ISC BIND versions 9 through 9.8.1-P1.");

  script_tag(name:"solution", value:"As a workaround it is recommended
  to clear the cache, which will remove cached bad records but is not an
  effective or practical preventative approach.");

  script_tag(name:"solution_type", value:"Workaround");

  script_xref(name:"URL", value:"https://www.kb.cert.org/vuls/id/542123");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/51898");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_isc_bind_consolidation.nasl");
  script_mandatory_keys("isc/bind/detected");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_full( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
proto = infos["proto"];
location = infos["location"];

if( version_in_range( version:version, test_version:"9.0", test_version2:"9.8.1p1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"Workaround", install_path:location );
  security_message( data:report, port:port, proto:proto );
  exit( 0 );
}

exit( 99 );
