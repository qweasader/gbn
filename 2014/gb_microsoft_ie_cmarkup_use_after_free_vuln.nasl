###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (2925418)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804500");
  script_version("2022-08-09T10:11:17+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0297", "CVE-2014-0298", "CVE-2014-0299", "CVE-2014-0302",
                "CVE-2014-0303", "CVE-2014-0304", "CVE-2014-0305", "CVE-2014-0306",
                "CVE-2014-0307", "CVE-2014-0308", "CVE-2014-0309", "CVE-2014-0311",
                "CVE-2014-0312", "CVE-2014-0313", "CVE-2014-0314", "CVE-2014-0321",
                "CVE-2014-0322", "CVE-2014-0324");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-08-09 10:11:17 +0000 (Tue, 09 Aug 2022)");
  script_tag(name:"creation_date", value:"2014-02-18 16:40:06 +0530 (Tue, 18 Feb 2014)");
  script_name("Microsoft Internet Explorer Multiple Memory Corruption Vulnerabilities (2925418)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-012.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to: error when handling CMarkup objects and multiple
  unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code,
  corrupt memory and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2925418");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65551");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66023");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66025");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66027");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66028");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66029");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66030");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66031");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66032");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66033");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66034");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66035");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66036");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66037");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66038");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66039");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66040");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/MS14-012");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win7:2, win2008:3, win8:1, win8_1:1) <= 0){
  exit(0);
}

ieVer = get_app_version(cpe:CPE);
if(!ieVer || ieVer !~ "^([6-9|1[01])\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Mshtml.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.2900.6512") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21370")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23568")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5294") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21370")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23568")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19040")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23329")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19506")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23568")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16539")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20650")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18391")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22596")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16539")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20650")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16842")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20962")||
     version_in_range(version:dllVer, test_version:"11.0.9600.16000", test_version2:"11.0.9600.16520")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16842")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.20962")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"11.0.9600.16000", test_version2:"11.0.9600.16520")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
