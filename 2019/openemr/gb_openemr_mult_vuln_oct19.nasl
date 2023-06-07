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
  script_oid("1.3.6.1.4.1.25623.1.0.113541");
  script_version("2021-09-06T14:01:33+0000");
  script_tag(name:"last_modification", value:"2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-10-09 13:12:41 +0000 (Wed, 09 Oct 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-08 15:25:00 +0000 (Tue, 08 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2019-17179", "CVE-2019-17197");

  script_name("OpenEMR < 5.0.2.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - There is an XSS vulnerability in library/custom_template/add_template.php
    via a crafted list_id query parameter.

  - There is an SQL Injection vulnerability in the Lifestyle demographic filter
    criteria in library/clinical_rules.php that affects library/patient.inc.");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to inject arbitrary
  HTML or JavaScript into the site, read sensitive information
  or execute arbitrary code on the target machine.");
  script_tag(name:"affected", value:"OpenEMR prior to version 5.0.2.1.");
  script_tag(name:"solution", value:"Update to version 5.0.2.1 or later.");

  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/2692");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/2698");
  script_xref(name:"URL", value:"https://github.com/openemr/openemr/pull/2701");

  exit(0);
}

CPE = "cpe:/a:open-emr:openemr";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE ) ) exit( 0 );
version = infos["version"];
location = infos["location"];

if( version_is_less( version: version, test_version: "5.0.2.1" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "5.0.2.1", install_path: location );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
