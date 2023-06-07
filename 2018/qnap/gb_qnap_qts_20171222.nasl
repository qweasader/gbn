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

CPE = "cpe:/o:qnap:qts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.113076");
  script_version("2022-05-25T12:01:55+0000");
  script_tag(name:"last_modification", value:"2022-05-25 12:01:55 +0000 (Wed, 25 May 2022)");
  script_tag(name:"creation_date", value:"2018-01-09 11:55:11 +0100 (Tue, 09 Jan 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-04 18:43:00 +0000 (Thu, 04 Jan 2018)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-17027", "CVE-2017-17028", "CVE-2017-17029", "CVE-2017-17030", "CVE-2017-17031", "CVE-2017-17032", "CVE-2017-17033");

  script_name("QNAP QTS Multiple RCE Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple remote code execution
  (RCE) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to
  execute arbitrary code on the machine.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.2.6 build 20171026, 4.3.3 build
  20171117, 4.3.4 build 20171116 and earlier.");

  script_tag(name:"solution", value:"Update to QNAP QTS version 4.2.6 build 20171208,
  4.3.3 build 20171205 or 4.3.4 build 20171208 respectively.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/nas-201712-15");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if ( ! version = get_app_version( cpe: CPE, nofork: TRUE ) )
  exit( 0 );

if( version_is_less( version: version, test_version: "4.2.6_20171208" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"4.2.6_20171208" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.3", test_version2: "4.3.3_20171117" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"4.3.3_20171205" );
  security_message( port: 0, data: report );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "4.3.4", test_version2: "4.3.4_20171117" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version:"4.3.4_20171208" );
  security_message( port: 0, data: report );
  exit( 0 );
}

exit( 99 );
