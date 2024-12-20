# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170145");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-08-08 08:33:24 +0000 (Mon, 08 Aug 2022)");
  script_tag(name:"cvss_base", value:"9.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-11 15:40:00 +0000 (Thu, 11 Aug 2022)");

  script_cve_id("CVE-2022-2303", "CVE-2022-2326", "CVE-2022-2456", "CVE-2022-2500");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab <= 15.0.4, 15.1.x - 15.1.3, 15.2 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-2303, CVE-2022-2326, CVE-2022-2456: Improper access control

  - CVE-2022-2500: stored cross-site scripting");

  script_tag(name:"impact", value:"It might be possible:

  - CVE-2022-2303: for group members to bypass 2FA enforcement enabled at the group level by using
  Resource Owner Password Credentials grant to obtain an access token without using 2FA.

  - CVE-2022-2326: to gain access to a private project through an email invite by using other user's
  email address as an unverified secondary email.

  - CVE-2022-2456: for malicious group or project maintainers to change their corresponding group or
  project visibility by crafting a malicious POST request.

  - CVE-2022-2500: to perform arbitrary actions on behalf of victims at client side.");

  script_tag(name:"affected", value:"GitLab version 15.0.4 and prior, 15.1.x through 15.1.3
  and 15.2.");

  script_tag(name:"solution", value:"Update to version 15.0.5, 15.1.4, 15.2.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/07/28/security-release-gitlab-15-2-1-released/");

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

if (version_is_less_equal( version:version, test_version:"15.0.4" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.0.5", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"15.1.0", test_version2:"15.1.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.1.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"15.2.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"15.2.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
