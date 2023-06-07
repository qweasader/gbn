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
  script_oid("1.3.6.1.4.1.25623.1.0.800079");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-12 16:11:26 +0100 (Fri, 12 Dec 2008)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2008-5314");
  script_name("ClamAV < 0.94.2 Remote DoS Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("clamav/detected");

  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2008/12/01/8");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32555");
  script_xref(name:"URL", value:"http://lurker.clamav.net/message/20081126.150241.55b1e092.en.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will cause remote attackers to crash the
  daemon via a specially crafted JPEG file.");

  script_tag(name:"affected", value:"ClamAV before versions 0.94.2.");

  script_tag(name:"insight", value:"The application fails to validate user input passed to
  cli_check_jpeg_exploit, jpeg_check_photoshop, and jpeg_check_photoshop_8bim functions in special.c
  file.");

  script_tag(name:"solution", value:"Update to version 0.94.2 or later.");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

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

if( version_is_less( version:vers, test_version:"0.94.2" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.94.2", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
