# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.12605");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-06-14 08:34:10 +0000 (Tue, 14 Jun 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 13.2 < 14.8.6, 14.9.0 < 14.9.4, 14.10 < 14.10.1 Information Disclosure Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host");

  script_tag(name:"impact", value:"It is possible to disclose details of confidential notes
  created via the API in Gitlab CE/EE if an unauthorised project member was tagged in the note.");

  script_tag(name:"affected", value:"GitLab version 13.2 through 14.8.5, 14.9.x through 14.9.3
  and version 14.10.0.");

  script_tag(name:"solution", value:"Update to version 14.8.6, 14.9.4, 14.10.1 or later.");

  script_xref(name:"URL", value:"https://about.gitlab.com/releases/2022/05/02/security-release-gitlab-14-10-1-released/");

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

if ( version_in_range( version:version, test_version:"13.2.0", test_version2:"14.8.5" ) ) {
    report = report_fixed_ver(installed_version: version, fixed_version: "14.8.6", install_path:location);
    security_message(port: port, data: report);
    exit(0);
}

if ( version_in_range( version:version, test_version:"14.9.0", test_version2:"14.9.3" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.9.4", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_is_equal( version:version, test_version:"14.10.0" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"14.10.1", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
