###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4038788)
#
# Authors:
# Kashinath T <tkashinath@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811671");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-8649", "CVE-2017-8660", "CVE-2017-8675", "CVE-2017-8737",
                "CVE-2017-8739", "CVE-2017-8740", "CVE-2017-8741", "CVE-2017-0161",
                "CVE-2017-11764", "CVE-2017-8719", "CVE-2017-8720", "CVE-2017-8723",
                "CVE-2017-8724", "CVE-2017-8728", "CVE-2017-8729", "CVE-2017-11766",
                "CVE-2017-8597", "CVE-2017-8628", "CVE-2017-8643", "CVE-2017-8648",
                "CVE-2017-8733", "CVE-2017-8734", "CVE-2017-8735", "CVE-2017-8736",
                "CVE-2017-8676", "CVE-2017-8677", "CVE-2017-8746", "CVE-2017-8747",
                "CVE-2017-8748", "CVE-2017-8678", "CVE-2017-8679", "CVE-2017-8749",
                "CVE-2017-8750", "CVE-2017-8751", "CVE-2017-8752", "CVE-2017-8753",
                "CVE-2017-8754", "CVE-2017-8681", "CVE-2017-8682", "CVE-2017-8755",
                "CVE-2017-8756", "CVE-2017-8757", "CVE-2017-8759", "CVE-2017-8683",
                "CVE-2017-8687", "CVE-2017-8688", "CVE-2017-8692", "CVE-2017-8695",
                "CVE-2017-8699", "CVE-2017-8706", "CVE-2017-8707", "CVE-2017-8708",
                "CVE-2017-8709", "CVE-2017-8712", "CVE-2017-8713", "CVE-2017-8716");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-09-13 09:31:28 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4038788)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB4038788");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"This security update includes improvements and
  fixes that resolves,

  - Internet Explorer 11's navigation bar with search box.

  - Internet Explorer where undo is broken if character conversion is canceled
    using IME.

  - Internet Explorer where graphics render incorrectly.

  - Internet Explorer where the Delete key functioned improperly.

  - NPS server where EAP TLS authentication was broken.

  - Security updates to Microsoft Graphics Component, Windows kernel-mode drivers,
    Windows shell, Microsoft Uniscribe, Microsoft Windows PDF Library, Windows TPM,
    Windows Hyper-V, Windows kernel, Windows DHCP Server, and Internet Explorer.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to get information on the Hyper-V host operating system, could
  retrieve the base address of the kernel driver from a compromised process, could
  obtain information to further compromise the users system.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1703 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4038788");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100754");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100757");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100752");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100749");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100761");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100763");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100764");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100728");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100726");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100768");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100777");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100739");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100733");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100745");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100744");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100747");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100750");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100738");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100740");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100743");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100755");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100767");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100760");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100765");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100766");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100769");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100720");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100770");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100771");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100775");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100776");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100779");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100727");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100772");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100778");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100718");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100721");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100742");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100781");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100736");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100756");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100762");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100773");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100783");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100789");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100790");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100791");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100792");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100795");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100796");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
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

if(version_in_range(version:edgeVer, test_version:"11.0.15063.0", test_version2:"11.0.15063.607"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.15063.0 - 11.0.15063.607\n' ;
  security_message(data:report);
  exit(0);
}
exit(0);