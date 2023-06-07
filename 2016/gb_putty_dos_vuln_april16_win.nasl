# Copyright (C) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:putty:putty";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807915");
  script_version("2021-10-11T13:01:25+0000");
  script_tag(name:"last_modification", value:"2021-10-11 13:01:25 +0000 (Mon, 11 Oct 2021)");
  script_tag(name:"creation_date", value:"2016-04-21 10:16:59 +0530 (Thu, 21 Apr 2016)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)");

  script_cve_id("CVE-2016-2563");

  script_tag(name:"qod_type", value:"registry");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PuTTY DoS Vulnerability April16 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_putty_portable_detect.nasl");
  script_mandatory_keys("putty/detected");

  script_tag(name:"summary", value:"PuTTY is prone to denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The SCP command-line utility (pscp) is missing a bounds-check
  for a stack buffer when processing the SCP-SINK file-size response to a SCP download request.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote servers to conduct a
  DoS attack.");

  script_tag(name:"affected", value:"PuTTY versions 0.59 through 0.66 on Windows.");

  script_tag(name:"solution", value:"Update to version 0.67 or later.");

  script_xref(name:"URL", value:"https://github.com/tintinweb/pub/tree/master/pocs/cve-2016-2563");
  script_xref(name:"URL", value:"http://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-pscp-sink-sscanf.html");

  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"0.59", test_version2:"0.66" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"0.67", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
