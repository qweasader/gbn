# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170072");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-28 13:44:07 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-27 19:41:00 +0000 (Wed, 27 Feb 2019)");

  script_cve_id("CVE-2018-9243");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.4.x - 10.4.6, 10.5.x - 10.5.6, 10.6.x - 10.6.2 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"When renaming a file, the file header shows a diff between the new
  and the old name on the /frans/test/merge_requests/3/diffs-page. When the diff is in the name (file
  was moved) the names of the file is not sanitized properly, triggering javascript inside the
  filename when accessing the /diffs-endpoint.");

  script_tag(name:"affected", value:"GitLab version 8.4.x through 10.4.6, 10.5.x through 10.5.6 and
  10.6.x through 10.6.2.");

  script_tag(name:"solution", value:"Update to version 10.4.7, 10.5.7, 10.6.3 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/42028");

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

if ( version_in_range( version:version, test_version:"8.4.0", test_version2:"10.4.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.4.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"10.5.0", test_version2:"10.5.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.5.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"10.6.0", test_version2:"10.6.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"10.6.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
