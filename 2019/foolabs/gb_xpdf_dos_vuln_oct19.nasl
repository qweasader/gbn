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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113538");
  script_version("2021-09-02T13:01:30+0000");
  script_tag(name:"last_modification", value:"2021-09-02 13:01:30 +0000 (Thu, 02 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-10-02 11:26:33 +0000 (Wed, 02 Oct 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-12-10 05:15:00 +0000 (Tue, 10 Dec 2019)");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_cve_id("CVE-2019-17064");

  script_name("Xpdf <= 4.02 Denial of Service (DoS) Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("secpod_xpdf_detect.nasl");
  script_mandatory_keys("Xpdf/Linux/Ver");

  script_tag(name:"summary", value:"Xpdf is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"There is a NULL pointer dereference because
  Catalog.pageLabels is initialized too late in the Catalog constructor.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to crash the application.");
  script_tag(name:"affected", value:"Xpdf through version 4.02.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_xref(name:"URL", value:"https://forum.xpdfreader.com/viewtopic.php?f=3&t=41890");
  script_xref(name:"URL", value:"http://www.xpdfreader.com/security-fixes.html");

  exit(0);
}

CPE = "cpe:/a:foolabs:xpdf";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less_equal( version: version, test_version: "4.02" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
  security_message( data: report, port: 0 );
  exit( 0 );
}

exit( 99 );
