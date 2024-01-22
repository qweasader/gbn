# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:gitlab:gitlab";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170057");
  script_version("2023-12-06T05:06:11+0000");
  script_tag(name:"last_modification", value:"2023-12-06 05:06:11 +0000 (Wed, 06 Dec 2023)");
  script_tag(name:"creation_date", value:"2022-03-25 19:01:02 +0000 (Fri, 25 Mar 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-27 12:42:00 +0000 (Thu, 27 Dec 2018)");

  script_cve_id("CVE-2018-18646");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("GitLab 5.3.x - 11.2.6, 11.3.x - 11.3.7, 11.4.x - 11.4.2 SSRF Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_gitlab_consolidation.nasl");
  script_mandatory_keys("gitlab/detected");

  script_tag(name:"summary", value:"GitLab is prone to a server-side request forgery (SSRF)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GitLab contains an issue which can be used by an attacker to make
  internal request to localhost i.e 127.0.0.1 and all local ip range.");

  script_tag(name:"affected", value:"GitLab version 5.3.x through 11.2.6, 11.3.x through 11.3.7 and
  11.4.x through 11.4.2.");

  script_tag(name:"solution", value:"Update to version 11.2.7, 11.3.8, 11.4.3 or later.");

  script_xref(name:"URL", value:"https://gitlab.com/gitlab-org/gitlab-foss/-/issues/51142");

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

if ( version_in_range( version:version, test_version:"5.3.0", test_version2:"11.2.6" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.2.7", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.3.0", test_version2:"11.3.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.3.8", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

if ( version_in_range( version:version, test_version:"11.4.0", test_version2:"11.4.2" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"11.4.3", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
