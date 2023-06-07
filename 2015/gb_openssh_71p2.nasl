###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH Client Information Leak
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105512");
  script_cve_id("CVE-2016-0777", "CVE-2016-0778");
  script_version("2021-10-18T09:03:47+0000");
  script_name("OpenSSH Client Information Leak");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-18 09:03:47 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-27 16:08:00 +0000 (Fri, 27 Dec 2019)");
  script_tag(name:"creation_date", value:"2016-01-14 17:31:53 +0100 (Thu, 14 Jan 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_openssh_consolidation.nasl");
  script_mandatory_keys("openssh/detected");

  script_xref(name:"URL", value:"http://www.openssh.com/txt/release-7.1p2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to 7.1p2 or newer.");

  script_tag(name:"summary", value:"The OpenSSH client code between 5.4 and 7.1p1 contains experimental support for resuming SSH-connections (roaming).
  The matching server code has never been shipped, but the client code was enabled by default and could be tricked by a malicious
  server into leaking client memory to the server, including private client user keys. The authentication of the server host key prevents exploitation
  by a man-in-the-middle, so this information leak is restricted to connections to malicious or compromised servers.");

  script_tag(name:"affected", value:"OpenSSH >= 5.4 < 7.1p2");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_in_range( version:vers, test_version:"5.4", test_version2:"7.1p1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.1p2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );