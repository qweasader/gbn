# SPDX-FileCopyrightText: 2021 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817981");
  script_version("2023-07-06T05:05:36+0000");
  script_cve_id("CVE-2021-28453");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-06 05:05:36 +0000 (Thu, 06 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-04 18:36:00 +0000 (Fri, 04 Jun 2021)");
  script_tag(name:"creation_date", value:"2021-04-14 09:40:14 +0530 (Wed, 14 Apr 2021)");
  script_name("Microsoft Word 2010 Remote Code Execution Vulnerability (KB4493218)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4493218");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error in
  Word Processing Software.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution.");

  script_tag(name:"affected", value:"Microsoft Word 2010.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4493218");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^14\." && version_is_less(version:exeVer, test_version:"14.0.7268.5000"))
{
  report = report_fixed_ver(file_checked:exePath + "winword.exe",
                            file_version:exeVer, vulnerable_range:"14.0 - 14.0.7268.4999");
  security_message(data:report);
  exit(0);
}
exit(99);
