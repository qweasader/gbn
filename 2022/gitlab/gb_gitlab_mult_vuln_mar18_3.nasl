# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170082");
  script_version("2024-11-15T05:05:36+0000");
  script_tag(name:"last_modification", value:"2024-11-15 05:05:36 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-0916", "CVE-2017-0920");

  # nb: Backported on Debian, see:
  # - https://www.debian.org/security/2018/dsa-4206
  # - https://www.debian.org/security/2018/dsa-4145
  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.8.x - 10.1.5, 10.2.x - 10.2.5, 10.3.x - 10.3.3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2017-0916: GitLab is vulnerable to a lack of input validation in the
  system_hook_push queue through web hook component resulting in remote code execution.

  - CVE-2017-0923: GitLab is vulnerable to an authorization bypass issue in the
   Projects::MergeRequests::CreationsController component resulting in an attacker to see every
   project name and their respective namespace on a GitLab instance.");

  script_tag(name:"affected", value:"GitLab version 8.8.x through 10.1.5, 10.2.x through 10.2.5 and
  10.3.x through 10.3.3.");

  script_tag(name:"solution", value:"Update to version 10.1.6, 10.2.6, 10.3.4 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2018/01/16/gitlab-10-dot-3-dot-4-released/");

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

if ( version_in_range( version:version, test_version:"8.8.0", test_version2:"10.1.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.1.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"10.2.0", test_version2:"10.2.5" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.2.6", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"10.3.0", test_version2:"10.3.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.3.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
