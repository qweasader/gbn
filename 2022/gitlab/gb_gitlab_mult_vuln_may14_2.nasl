# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170092");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-28 08:06:32 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2013-4580", "CVE-2013-4581");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab Community Edition 4.2.x - 5.4.1, 6.x - 6.2.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_exclude_keys("gitlab/ee/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2013-4580: unauthenticated API access to GitLab when using MySQL

  - CVE-2013-4581: remote code execution vulnerability via Git SSH access");

  script_tag(name:"affected", value:"GitLab version 4.2.x through 5.4.1 and 6.x through 6.2.3");

  script_tag(name:"solution", value:"Update to version 5.4.2, 6.2.4 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2013/11/14/multiple-critical-vulnerabilities-in-gitlab/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if ( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if ( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if ( version_is_less( version:version, test_version:"5.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"5.4.2", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"6.0.0", test_version2:"6.2.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"6.2.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
