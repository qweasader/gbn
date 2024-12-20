# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113177");
  script_version("2024-02-09T05:06:25+0000");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-05-08 13:53:45 +0200 (Tue, 08 May 2018)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2017-7489", "CVE-2017-7490", "CVE-2017-7491");

  script_name("Moodle 2.x / 3.x Multiple Vulnerabilities (May 2017) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_moodle_cms_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("moodle/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Moodle is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  Remote authenticated users can take ownership of arbitrary blogs by editing an external blog link.

  Searching of arbitrary blogs is possible because a capability check is missing.

  A CSRF attack is possible that allows attackers to change the
  'number of courses displayed in the course overview block' configuration setting.");
  script_tag(name:"impact", value:"Successful exploitation could result in effects ranging from
  information disclosure to an attacker gaining complete ownership of the blog.");
  script_tag(name:"affected", value:"Moodle versions through 2.7.19, 2.8.0 through 3.0.9, 3.1.0 through 3.1.5
  and 3.2.0 through 3.2.2.");
  script_tag(name:"solution", value:"Update to version 2.7.20, 3.0.10, 3.1.6 or 3.2.3 respectively.");

  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=352353");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=352354");
  script_xref(name:"URL", value:"https://moodle.org/mod/forum/discuss.php?d=352355");

  exit(0);
}

CPE = "cpe:/a:moodle:moodle";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( port: port, cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
version = infos['version'];
path = infos['location'];

if( version_is_less( version: version, test_version: "2.7.20" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "2.7.20", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "2.8.0", test_version2: "3.0.9" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.0", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.1.0", test_version2: "3.1.5" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.1.6", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

if( version_in_range( version: version, test_version: "3.2.0", test_version2: "3.2.2" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "3.2.3", install_path: path );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
