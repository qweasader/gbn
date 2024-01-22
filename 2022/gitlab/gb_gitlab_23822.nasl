# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170084");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-11-29 19:15:00 +0000 (Tue, 29 Nov 2016)");

  script_cve_id("CVE-2016-9086");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.9.x - 8.10.12, 8.11.x - 8.11.9, 8.12.x - 8.12.7, 8.13.x - 8.13.2 Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a directory traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Directory traversal via 'import/export' feature:

  This feature did not properly check for symbolic links in user-provided archives and therefore it
  was possible for an authenticated user to retrieve the contents of any file accessible to the
  GitLab service account. This included sensitive files such as those that contain secret tokens
  used by the GitLab service to authenticate users.");

  script_tag(name:"affected", value:"GitLab version 8.9.x through 8.10.12, 8.11.x through 8.11.9,
  8.12.x through 8.12.7 and 8.13.x through 8.13.2.");

  script_tag(name:"solution", value:"Update to version 8.10.13, 8.11.10, 8.12.8, 8.13.3 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2016/11/02/cve-2016-9086-patches/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/23822");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_in_range( version:version, test_version:"8.9.0", test_version2:"8.10.12" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.10.13", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"8.11.0", test_version2:"8.11.9" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.11.10", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"8.12.0", test_version2:"8.12.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.12.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if( version_in_range( version:version, test_version:"8.13.0", test_version2:"8.13.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"8.13.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
