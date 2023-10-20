# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.812135");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-11831");
  script_tag(name:"cvss_base", value:"4.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-11-30 19:10:00 +0000 (Thu, 30 Nov 2017)");
  script_tag(name:"creation_date", value:"2017-11-15 08:06:37 +0530 (Wed, 15 Nov 2017)");
  script_name("Microsoft Windows Information Disclosure Vulnerability (KB4046184)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4046184");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to the Windows kernel fails
  to properly initialize a memory address.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system.");

  script_tag(name:"affected", value:"Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4046184");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/101721");
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

if(hotfix_check_sp(win2008:3, win2008x64:3) <= 0){
  exit(0);
}

Path = smb_get_system32root();
if(!Path ){
  exit(0);
}

fileVer = fetch_file_version(sysPath:Path, file_name:"drivers\luafv.sys");
if(!fileVer){
  exit(0);
}

if(version_is_less(version:fileVer, test_version:"6.0.6002.24215"))
{
  report = report_fixed_ver(file_checked:Path + "\drivers\luafv.sys",
                            file_version:fileVer, vulnerable_range:"Less than 6.0.6002.24215");
  security_message(data:report);
  exit(0);
}
exit(0);
