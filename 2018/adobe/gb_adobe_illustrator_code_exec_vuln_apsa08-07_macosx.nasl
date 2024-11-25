# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:illustrator";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813495");
  script_version("2024-06-28T15:38:46+0000");
  script_cve_id("CVE-2008-3961");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-06-28 15:38:46 +0000 (Fri, 28 Jun 2024)");
  script_tag(name:"creation_date", value:"2018-07-12 15:41:49 +0530 (Thu, 12 Jul 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Illustrator Remote Code Execution Vulnerability-Mac OS X (apsa08-07)");

  script_tag(name:"summary", value:"Adobe Illustrator is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error where a
  crafted file gets loaded by the application.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Adobe Illustrator CS2 all versions.");

  script_tag(name:"solution", value:"Upgrade to Adobe Illustrator CS3 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://www.adobe.com/support/security/advisories/apsa08-07.html");

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_adobe_illustrator_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Illustrator/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
adobeVer = infos['version'];
adobePath = infos['location'];

if(adobeVer =~ "^12\.")
{
  report = report_fixed_ver(installed_version:adobeVer, fixed_version:"Adobe Illustrator CS3", install_path:adobePath);
  security_message(data: report);
  exit(0);
}
exit(0);
