# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:creative_cloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826716");
  script_version("2024-02-27T14:36:53+0000");
  script_cve_id("CVE-2021-21068", "CVE-2021-21069", "CVE-2021-21078", "CVE-2021-28547");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-27 14:36:53 +0000 (Tue, 27 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 03:29:00 +0000 (Tue, 07 Nov 2023)");
  script_tag(name:"creation_date", value:"2022-11-30 00:57:19 +0530 (Wed, 30 Nov 2022)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Creative Cloud Security Update (APSB21-18) - Windows");

  script_tag(name:"summary", value:"Adobe Creative cloud is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An arbitrary file overwrite vulnerability.

  - OS Command Injection.

  - An improper input validation.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and escalate privileges on the target system.");

  script_tag(name:"affected", value:"Adobe Creative Cloud 5.3 and earlier versions on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Creative Cloud version
  5.4. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/creative-cloud/apsb21-18.html");
  script_xref(name:"URL", value:"https://helpx.adobe.com/creative-cloud");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_creative_cloud_detect_win.nasl");
  script_mandatory_keys("AdobeCreativeCloud/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
cloudVer = infos["version"];
cloudPath = infos["location"];

if(version_is_less(version:cloudVer, test_version:"5.4"))
{
  report = report_fixed_ver(installed_version:cloudVer, fixed_version:"5.4", install_path:cloudPath);
  security_message(data:report);
  exit(0);
}
exit(0);
