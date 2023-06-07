###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Multiple Vulnerabilities (KB4019473)
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
  script_oid("1.3.6.1.4.1.25623.1.0.811110");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2017-0064", "CVE-2017-0077", "CVE-2017-0190", "CVE-2017-0212",
                "CVE-2017-0213", "CVE-2017-0214", "CVE-2017-0222", "CVE-2017-0226",
                "CVE-2017-0227", "CVE-2017-0228", "CVE-2017-0229", "CVE-2017-0231",
                "CVE-2017-0233", "CVE-2017-0234", "CVE-2017-0236", "CVE-2017-0238",
                "CVE-2017-0240", "CVE-2017-0241", "CVE-2017-0246", "CVE-2017-0248",
                "CVE-2017-0258", "CVE-2017-0259", "CVE-2017-0263", "CVE-2017-0266",
                "CVE-2017-0267", "CVE-2017-0268", "CVE-2017-0269", "CVE-2017-0270",
                "CVE-2017-0271", "CVE-2017-0272", "CVE-2017-0273", "CVE-2017-0274",
                "CVE-2017-0275", "CVE-2017-0276", "CVE-2017-0277", "CVE-2017-0278",
                "CVE-2017-0279", "CVE-2017-0280");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");
  script_tag(name:"creation_date", value:"2017-05-10 08:55:53 +0530 (Wed, 10 May 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Windows Multiple Vulnerabilities (KB4019473)");

  script_tag(name:"summary", value:"This host is missing a critical/important
  security update according to Microsoft KB4019473.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to obtain information to further compromise the user's system, execute
  arbitrary code in the context of the current user, gain the same user rights as
  the current user, could take control of an affected system, spoof content, bypass
  certain security restrictions and cause a host machine to crash.");

  script_tag(name:"affected", value:"Microsoft Windows 10 Version 1511 x32/x64.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-gb/help/4019473");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98121");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98114");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98298");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98099");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98102");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98103");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98127");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98139");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98281");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98217");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98173");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98179");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98229");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98234");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98237");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98203");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98208");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98108");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98117");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98112");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98113");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98258");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98276");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98259");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98261");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98263");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98264");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98265");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98260");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98274");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98266");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98268");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98270");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98272");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/98273");
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

edgeVer = fetch_file_version(sysPath:sysPath, file_name:"Edgehtml.dll");
if(!edgeVer){
  exit(0);
}

if(version_in_range(version:edgeVer, test_version:"11.0.10586.0", test_version2:"11.0.10586.915"))
{
  report = 'File checked:     ' + sysPath + "\Edgehtml.dll" + '\n' +
           'File version:     ' + edgeVer  + '\n' +
           'Vulnerable range: 11.0.10586.0 - 11.0.10586.915\n' ;
  security_message(data:report);
  exit(0);
}
