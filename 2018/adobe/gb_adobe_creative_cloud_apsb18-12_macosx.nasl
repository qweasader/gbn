# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813363");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2018-4873", "CVE-2018-4991", "CVE-2018-4992");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-06-25 13:52:00 +0000 (Mon, 25 Jun 2018)");
  script_tag(name:"creation_date", value:"2018-05-11 14:17:30 +0530 (Fri, 11 May 2018)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Creative Cloud Security Updates APSB18-12 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Creative cloud is prone to multiple vulnerabilities");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An improper input validation.

  - An improper certificate validation.

  - An unquoted search path error.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to escalate privileges and bypass security restrictions.");

  script_tag(name:"affected", value:"Adobe Creative Cloud before 4.5.0.331
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  4.5.0.331 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb18-12.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104103");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_macosx.nasl");
  script_mandatory_keys("AdobeCreativeCloud/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos['version'];
cloudPath = infos['location'];

if(version_is_less(version:cloudVer, test_version:"4.5.0.331"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"4.5.0.331", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
