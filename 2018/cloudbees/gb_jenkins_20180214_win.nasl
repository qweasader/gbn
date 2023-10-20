# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112228");
  script_version("2023-07-20T05:05:17+0000");

  script_cve_id("CVE-2018-6356", "CVE-2018-1000067", "CVE-2018-1000068");

  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-13 19:09:00 +0000 (Mon, 13 Jun 2022)");
  script_tag(name:"creation_date", value:"2018-02-19 11:00:00 +0100 (Mon, 19 Feb 2018)");

  script_name("Jenkins < 2.107 and < 2.89.4 LTS Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_jenkins_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("jenkins/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-02-14/");

  script_tag(name:"summary", value:"Jenkins is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Jenkins is prone to the following vulnerabilities:

  - Path traversal vulnerability which allows access to files outside plugin resources. (CVE-2018-6356)

  - Improperly secured form validation for proxy configuration, allowing Server-Side Request Forgery. (CVE-2018-1000067)

  - Improper input validation, allowing unintended access to plugin resource files on case-insensitive file systems. (CVE-2018-1000068)");

  script_tag(name:"affected", value:"Jenkins LTS up to and including 2.89.3, Jenkins weekly up to and including 2.106.");

  script_tag(name:"solution", value:"Upgrade to Jenkins weekly to 2.107 or later / Jenkins LTS to 2.89.4 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_full(cpe: CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];
proto = infos["proto"];

if( get_kb_item( "jenkins/" + port + "/is_lts" ) ) {
  if ( version_is_less( version:version, test_version:"2.89.4" ) ) {
    vuln = TRUE;
    fix = "2.89.4";
  }
} else {
  if( version_is_less( version:version, test_version:"2.107" ) ) {
    vuln = TRUE;
    fix = "2.107";
  }
}

if( vuln ) {
  report = report_fixed_ver( installed_version:version, fixed_version:fix, install_path:location );
  security_message( port:port, data:report, proto:proto );
  exit( 0 );
}

exit( 99 );
