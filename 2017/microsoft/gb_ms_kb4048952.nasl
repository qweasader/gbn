# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812136");
  script_version("2023-11-03T05:05:46+0000");
  script_cve_id("CVE-2017-11863", "CVE-2017-11866", "CVE-2017-11869", "CVE-2017-11873",
                "CVE-2017-11768", "CVE-2017-11788", "CVE-2017-11880", "CVE-2017-11791",
                "CVE-2017-11827", "CVE-2017-11834", "CVE-2017-11836", "CVE-2017-11837",
                "CVE-2017-11838", "CVE-2017-11839", "CVE-2017-11840", "CVE-2017-11841",
                "CVE-2017-11842", "CVE-2017-11843", "CVE-2017-11846", "CVE-2017-11847",
                "CVE-2017-11848", "CVE-2017-11849", "CVE-2017-11850", "CVE-2017-11851",
                "CVE-2017-11853", "CVE-2017-11855", "CVE-2017-11856", "CVE-2017-11858",
                "CVE-2017-11830", "CVE-2017-11831", "CVE-2017-11833");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-11-15 08:08:33 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4048952)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4048952");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This update includes critical security updates

  - Addressed issue with the rendering of a graphics element in Internet Explorer.

  - Addressed issue where access to the Trusted Platform Module (TPM) for
    administrative operations wasn't restricted to administrative users.

  - Addressed issue where applications based on the Microsoft JET Database Engine
    fail when creating or opening Microsoft Excel .xls files.

  - Addressed a crash in Internet Explorer that was seen in machines that used large
    font-size settings.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain the same user rights as the current user, and obtain information to further
  compromise the user's system. Also attacker can run arbitrary code in kernel mode.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4048952");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101748");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101732");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101705");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101711");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101715");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101725");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101722");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101735");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101734");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101719");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101709");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101751");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101753");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101716");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101714");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101706");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win10:1, win10x64:1) <= 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.1231"))
{
  report = report_fixed_ver(file_checked:sysPath + "\Edgehtml.dll",
                            file_version:edgeVer, vulnerable_range:"11.0.10586.0 - 11.0.10586.1231");
  security_message(data:report);
  exit(0);
}
exit(0);
