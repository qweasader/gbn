# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810566");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2016-4613", "CVE-2016-4666", "CVE-2016-4677", "CVE-2016-7578");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-13 15:14:00 +0000 (Wed, 13 Mar 2019)");
  script_tag(name:"creation_date", value:"2017-02-22 14:46:57 +0530 (Wed, 22 Feb 2017)");
  script_name("Apple Safari Code Execution And Information Disclosure Vulnerabilities Feb17");

  script_tag(name:"summary", value:"Apple Safari is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Multiple memory corruption issues in WebKit.

  - An input validation issue in state management.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to disclose sensitive information and can also lead to arbitrary
  code execution.");

  script_tag(name:"affected", value:"Apple Safari versions before 10.0.1");

  script_tag(name:"solution", value:"Upgrade to Apple Safari version 10.0.1 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT207272");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!safVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:safVer, test_version:"10.0.1"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"10.0.1");
  security_message(data:report);
  exit(0);
}
