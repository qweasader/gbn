# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815501");
  script_version("2023-10-06T16:09:51+0000");
  script_cve_id("CVE-2019-1134", "CVE-2019-1006");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-10-06 16:09:51 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2019-07-10 13:27:24 +0530 (Wed, 10 Jul 2019)");
  script_name("Microsoft SharePoint Enterprise Server 2016 Multiple Vulnerabilities (KB4475520)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4475520");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An authentication bypass vulnerability exists in Windows Communication
    Foundation (WCF) and Windows Identity Foundation (WIF), allowing signing
    of SAML tokens with arbitrary symmetric keys.

  - A cross-site-scripting (XSS) vulnerability exists when Microsoft SharePoint
    Server does not properly sanitize a specially crafted web request to an affected
    SharePoint server.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to perform cross-site scripting attacks on affected systems and run script in
  the security context of the current user and read content that the attacker is
  not authorized to read, use the victim's identity to take actions on the
  SharePoint site on behalf of the user.");

  script_tag(name:"affected", value:"Microsoft SharePoint Enterprise Server 2016.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4475520");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/109028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/108978");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_sharepoint_sever_n_foundation_detect.nasl");
  script_mandatory_keys("MS/SharePoint/Server/Ver");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

CPE = "cpe:/a:microsoft:sharepoint_server";

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

shareVer = infos["version"];
if(shareVer !~ "^16\.")
  exit(0);

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion");
}
else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion");
}

foreach key(key_list)
{
  path = registry_get_sz(key:key, item:"CommonFilesDir");

  if(path)
  {
    path = path + "\microsoft shared\Web Server Extensions\16\BIN";
    dllVer = fetch_file_version(sysPath:path, file_name:"Onetutil.dll");
    if(dllVer =~ "^16\." && version_is_less(version:dllVer, test_version:"16.0.4873.1000"))
    {
      report = report_fixed_ver(file_checked:path + "\Onetutil.dll",
                                file_version:dllVer, vulnerable_range:"16.0 - 16.0.4873.0999");
      security_message(port:0, data:report);
      exit(0);
    }
  }
}

exit(99);
