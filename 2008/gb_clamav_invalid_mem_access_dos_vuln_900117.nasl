# Copyright (C) 2008 Greenbone Networks GmbH
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

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900117");
  script_version("2022-05-11T11:17:52+0000");
  script_cve_id("CVE-2008-1389");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-09-05 16:50:44 +0200 (Fri, 05 Sep 2008)");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("ClamAV < 0.94 Invalid Memory Access DoS Vulnerability");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("clamav/detected");

  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/2484");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/30994");
  script_xref(name:"URL", value:"http://svn.clamav.net/svn/clamav-devel/trunk/ChangeLog");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an invalid memory access in chmunpack.c
  file, when processing a malformed CHM file.");

  script_tag(name:"affected", value:"ClamAV versions prior to 0.94.");

  script_tag(name:"solution", value:"Update to version 0.94 or later.");

  script_tag(name:"impact", value:"Successful remote exploitation will allow attackers to cause
  the application to crash.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.94" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.94", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
