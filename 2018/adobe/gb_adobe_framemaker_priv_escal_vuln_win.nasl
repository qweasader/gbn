# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:framemaker";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814315");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-15974");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-12-17 16:18:00 +0000 (Mon, 17 Dec 2018)");
  script_tag(name:"creation_date", value:"2018-10-15 12:43:10 +0530 (Mon, 15 Oct 2018)");
  script_name("Adobe FrameMaker Privilege Escalation Vulnerability (Windows)");

  script_tag(name:"summary", value:"Adobe FrameMaker is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw exists because when the application
  looks to load a DLL for execution, an attacker can provide a malicious DLL to use
  instead. The vulnerability can be exploited by a simple file write (or potentially
  an over-write) which results in a foreign DLL running under the application.");

  script_tag(name:"impact", value:"Successful exploitation allows a local attackers
  to gain elevated privileges and execute arbitrary code on the vulnerable system.");

  script_tag(name:"affected", value:"Adobe FrameMaker versions 1.0.5.1 and before.");

  script_tag(name:"solution", value:"Update to Adobe FrameMaker 2019 Release or
  later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/framemaker/apsb18-37.html");
  script_xref(name:"URL", value:"https://fortiguard.com/zeroday/2219");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_adobe_framemaker_detect_win.nasl");
  script_mandatory_keys("AdobeFrameMaker/Win/Ver");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
frameVer = infos['version'];
framePath = infos['location'];

if(version_is_less(version:frameVer, test_version:"1.0.5.1"))
{
  report = report_fixed_ver(installed_version:frameVer, fixed_version:"2019 Release", install_path:framePath);
  security_message(data:report);
  exit(0);
}
