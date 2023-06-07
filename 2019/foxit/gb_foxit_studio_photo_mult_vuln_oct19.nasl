# Copyright (C) 2019 Greenbone Networks GmbH
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

CPE = "cpe:/a:foxitsoftware:foxit_studio_photo";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107727");
  script_version("2021-08-30T13:01:21+0000");
  script_cve_id("CVE-2019-13323", "CVE-2019-13324", "CVE-2019-13325");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-08-30 13:01:21 +0000 (Mon, 30 Aug 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:46:00 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-12 19:07:16 +0200 (Sat, 12 Oct 2019)");

  script_name("Foxit Software Foxit Studio Photo <= 3.6.6.911 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"Foxit Studio Photo is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The vulnerabilities exist due to the lack of proper validation
  of user-supplied data, which can result in:

  - A write past the end of an allocated structure - due to a flaw within the handling of TIFF files (CVE-2019-13323)

  - A read past the end of an allocated structure - due to a flaw within the handling of TIFF files (CVE-2019-13324)

  - A read past the end of an allocated structure - due to a flaw within the handling of EPS files (CVE-2019-13325)

  Note: User interaction is required to exploit these vulnerabilities in that the target must visit
  a malicious page or open a malicious file.");

  script_tag(name:"impact", value:"Successful exploitation of these vulnerabilities could allow a remote attacker
  to execute arbitrary code on affected installations of Foxit Studio Photo.");

  script_tag(name:"affected", value:"Foxit Studio Photo through version 3.6.6.911.");

  script_tag(name:"solution", value:"Update to Foxit Studio Photo version 3.6.6.913 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://www.foxitsoftware.com/support/security-bulletins.php");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_foxit_studio_photo_detect.nasl");
  script_mandatory_keys("foxitsoftware/foxit_studio_photo/detected");
  exit(0);
}

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

version = infos['version'];
location = infos['location'];

if( version_is_less_equal( version:version, test_version:"3.6.6.911" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.6.6.913", install_path:location );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );
