# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170075");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-28 14:21:05 +0000 (Mon, 28 Mar 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-09 23:21:00 +0000 (Wed, 09 Oct 2019)");

  script_cve_id("CVE-2017-0927");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 8.16.x - 9.5.10, 10.x - 10.1.5, 10.2.x - 10.2.5, 10.3.x - 10.3.3 Improper Authorization Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to multiple improper authorization
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Guest users can give deploy keys in other projects write access");

  script_tag(name:"affected", value:"GitLab version 8.16.x through 9.5.10, 10.x through 10.1.5,
  10.2.x through 10.2.5 and 10.3.x through 10.3.3.");

  script_tag(name:"solution", value:"Update to version 9.5.11, 10.1.6, 10.2.6, 10.3.4 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2018/01/16/gitlab-10-dot-3-dot-4-released/");
  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/37594");

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

if ( version_in_range( version:version, test_version:"8.16.0", test_version2:"9.5.10" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"9.5.11", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"10.0.0", test_version2:"10.1.5" ) ) {
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
