# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:oracle:openjdk";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.150651");
  script_version("2023-10-20T16:09:12+0000");
  script_tag(name:"last_modification", value:"2023-10-20 16:09:12 +0000 (Fri, 20 Oct 2023)");
  script_tag(name:"creation_date", value:"2021-05-31 08:42:17 +0000 (Mon, 31 May 2021)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-08 13:00:00 +0000 (Tue, 08 Sep 2020)");

  script_cve_id("CVE-2019-2949", "CVE-2019-2989", "CVE-2019-2958", "CVE-2019-2975", "CVE-2019-2977",
                "CVE-2019-2999", "CVE-2019-2981", "CVE-2019-2973", "CVE-2019-2983", "CVE-2019-2988",
                "CVE-2019-2978", "CVE-2019-2964", "CVE-2019-2992", "CVE-2019-2962", "CVE-2019-2987",
                "CVE-2019-2894", "CVE-2019-2933", "CVE-2019-2945");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Oracle OpenJDK Multiple Vulnerabilities (Oct 2019)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_openjdk_detect.nasl");
  script_mandatory_keys("openjdk/detected");

  script_tag(name:"summary", value:"Oracle OpenJDK is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Please see the references for more information on the
  vulnerabilities.");

  script_tag(name:"affected", value:"Oracle OpenJDK versions 13, 11.0.4, 8u222 (1.8.0.222), 7u231
  (1.7.0.231) and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_xref(name:"URL", value:"https://openjdk.java.net/groups/vulnerability/advisories/2019-10-15");

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

if( version_is_equal( version:vers, test_version:"13.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^11" && version_is_less_equal( version:vers, test_version:"11.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^1\.8" && version_is_less_equal( version:vers, test_version:"1.8.0.222" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

if( vers =~ "^1\.7" && version_is_less_equal( version:vers, test_version:"1.7.0.231" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See advisory", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );