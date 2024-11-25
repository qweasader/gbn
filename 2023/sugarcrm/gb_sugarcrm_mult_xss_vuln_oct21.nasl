# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:sugarcrm:sugarcrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126290");
  script_version("2024-04-12T15:39:03+0000");
  script_tag(name:"last_modification", value:"2024-04-12 15:39:03 +0000 (Fri, 12 Apr 2024)");
  script_tag(name:"creation_date", value:"2023-01-09 11:50:46 +0000 (Mon, 09 Jan 2023)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-28 16:55:00 +0000 (Thu, 28 Oct 2021)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_cve_id("CVE-2020-28955", "CVE-2020-28956", "CVE-2020-36501");

  script_name("SugarCRM < 6.5.18 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_sugarcrm_detect.nasl");
  script_mandatory_keys("sugarcrm/installed");

  script_tag(name:"summary", value:"SugarCRM is prone to multiple cross-site scripting (XSS)
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2020-28955: XSS in create employee module

  - CVE-2020-28956: Multiple XSS in the sales module

  - CVE-2020-36501: Multiple XSS in the support module");

  script_tag(name:"affected", value:"SugarCRM version 6.5.18 and probably prior.");

  script_tag(name:"solution", value:"Please refer to the vendor advisory for a workaround.");

  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2249");
  script_xref(name:"URL", value:"https://www.vulnerability-lab.com/get_content.php?id=2257");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

version = infos["version"];
location = infos["location"];

if( version_is_less( version:version, test_version:"6.5.18" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"See solution", install_path:location );
  security_message( port: port, data:report );
  exit( 0 );
}

exit( 99 );
