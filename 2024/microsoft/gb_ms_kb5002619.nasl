# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.834749");
  script_version("2024-11-15T15:55:05+0000");
  script_cve_id("CVE-2024-49033");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-15 15:55:05 +0000 (Fri, 15 Nov 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-12 18:15:43 +0000 (Tue, 12 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-11-14 09:40:17 +0530 (Thu, 14 Nov 2024)");
  script_name("Microsoft Word 2016 Security Feature Bypass Vulnerability (KB5002619)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB5002619");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a security feature
  bypass vulnerability in microsoft word.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to bypass security restrictions.");

  script_tag(name:"affected", value:"Microsoft Word 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/5002619");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer) {
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath) {
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^16\." && version_is_less(version:exeVer, test_version:"16.0.5474.1000")) {
  report = report_fixed_ver(file_checked:exePath + "winword.exe", file_version:exeVer, vulnerable_range:"16.0 - 16.0.5474.0999");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
