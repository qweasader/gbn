# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:vm2_project:vm2";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170444");
  script_version("2023-10-13T05:06:10+0000");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-05-02 17:41:06 +0000 (Tue, 02 May 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-28 01:13:00 +0000 (Fri, 28 Apr 2023)");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2023-30547");

  script_name("vm2 < 3.9.17 Sandbox Escape Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("General");
  script_dependencies("gb_javascript_packages_consolidation.nasl");
  script_mandatory_keys("javascript_package/vm2/detected");

  script_tag(name:"summary", value:"vm2 is prone to a sandbox escape vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"There exists a vulnerability in exception sanitization of vm2,
  allowing attackers to raise an unsanitized host exception inside handleException() which can be used
  to escape the sandbox and run arbitrary code in host context.");

  script_tag(name:"impact", value:"A threat actor can bypass the sandbox protections to gain remote
  code execution rights on the host running the sandbox.");

  script_tag(name:"affected", value:"vm2 prior to version 3.9.17.");

  script_tag(name:"solution", value:"Update to version 3.9.17 or later.");

  script_xref(name:"URL", value:"https://github.com/patriksimek/vm2/security/advisories/GHSA-ch3r-j5x3-6q2m");
  script_xref(name:"URL", value:"https://gist.github.com/leesh3288/381b230b04936dd4d74aaf90cc8bb244");

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

if ( version_is_less( version:version, test_version:"3.9.17" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"3.9.17", install_path:location );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
