# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.170131");
  script_version("2022-08-09T10:11:17+0000");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-06-23 12:03:37 +0000 (Thu, 23 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)");

  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2019-11043");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS RCE Vulnerability (QSA-22-20)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_http_detect.nasl");
  script_mandatory_keys("qnap/nas/qts/detected");

  script_tag(name:"summary", value:"QNAP QTS is prone to a remote code execution (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability has been reported to affect PHP versions 7.1.x
  below 7.1.33, 7.2.x below 7.2.24, and 7.3.x below 7.3.11 with improper nginx configuration. For the
  vulnerability to be exploited, both nginx and php-fpm must be running.

  While QTS do not have nginx installed by default, your QNAP NAS may still be affected if you have
  installed and are running nginx and php-fpm on your NAS.");

  script_tag(name:"impact", value:"If exploited, the vulnerability allows attackers to gain remote
  code execution.");

  script_tag(name:"affected", value:"QNAP QTS versions 4.5.x and 5.0.x.");

  script_tag(name:"solution", value:"Update to version 5.0.1.2034 build 20220515 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/QSA-22-20");
  script_xref(name:"URL", value:"https://www.qnap.com/en/release-notes/qts/5.0.1.2034/20220515");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( ! version = get_app_version( cpe:CPE, nofork:TRUE ) )
  exit( 0 );

if ( version_in_range_exclusive( version:version, test_version_lo:"4.5.0", test_version_up:"5.0.1_20220515" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.0.1_20220515" );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
