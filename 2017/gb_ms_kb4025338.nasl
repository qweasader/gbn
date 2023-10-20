# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811461");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8595", "CVE-2017-8599", "CVE-2017-8601", "CVE-2017-8602",
                "CVE-2017-0170", "CVE-2017-8463", "CVE-2017-8605", "CVE-2017-8606",
                "CVE-2017-8607", "CVE-2017-8608", "CVE-2017-8467", "CVE-2017-8486",
                "CVE-2017-8609", "CVE-2017-8611", "CVE-2017-8618", "CVE-2017-8619",
                "CVE-2017-8495", "CVE-2017-8556", "CVE-2017-8557", "CVE-2017-8561",
                "CVE-2017-8562", "CVE-2017-8563", "CVE-2017-8564", "CVE-2017-8565",
                "CVE-2017-8573", "CVE-2017-8577", "CVE-2017-8578", "CVE-2017-8580",
                "CVE-2017-8581", "CVE-2017-8582", "CVE-2017-8585", "CVE-2017-8587",
                "CVE-2017-8588", "CVE-2017-8589", "CVE-2017-8590", "CVE-2017-8592");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-07-12 08:32:30 +0530 (Wed, 12 Jul 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4025338)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4025338");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Microsoft Windows when Win32k fails to properly handle objects in memory.

  - The way that the Scripting Engine renders when handling objects in memory
    in Microsoft browsers.

  - The way JavaScript engines render when handling objects in memory in
    Microsoft browsers.

  - The way Microsoft Edge handles objects in memory.

  - When Windows Explorer improperly handles executable files and shares during
    rename operations.

  - when an affected Microsoft browser does not properly parse HTTP content.

  - when Windows improperly handles calls to Advanced Local Procedure Call (ALPC).

  - When Kerberos falls back to NT LAN Manager (NTLM) Authentication Protocol as
    the default authentication protocol.

  - The way that the Windows Kernel handles objects in memory.

  - The Microsoft Graphics Component fails to properly handle
    objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to gain the same user rights as
  the current user, run arbitrary code, processes with elevated privileges.
  Also could take control of the affected system and cause denial of service.");

  script_tag(name:"affected", value:"Microsoft Windows 10 for x86/x64-based Systems.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4025338");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99403");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99393");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99420");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99390");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99389");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99388");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99408");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99410");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99412");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99409");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99414");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99391");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99399");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99392");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99424");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99439");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99398");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99426");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99397");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99402");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99428");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99394");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99431");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99416");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99419");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99421");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99423");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99429");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99432");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99413");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99400");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99425");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99427");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99396");
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

if(version_is_less(version:edgeVer, test_version:"11.0.10240.17488"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: Less than 11.0.10240.17488\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);
