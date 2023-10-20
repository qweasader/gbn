# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:ie";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804595");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0282", "CVE-2014-1762", "CVE-2014-1764", "CVE-2014-1766",
                "CVE-2014-1769", "CVE-2014-1770", "CVE-2014-1771", "CVE-2014-1772",
                "CVE-2014-1773", "CVE-2014-1774", "CVE-2014-1775", "CVE-2014-1777",
                "CVE-2014-1778", "CVE-2014-1779", "CVE-2014-1780", "CVE-2014-1781",
                "CVE-2014-1782", "CVE-2014-1783", "CVE-2014-1784", "CVE-2014-1785",
                "CVE-2014-1786", "CVE-2014-1788", "CVE-2014-1789", "CVE-2014-1790",
                "CVE-2014-1791", "CVE-2014-1792", "CVE-2014-1794", "CVE-2014-1795",
                "CVE-2014-1796", "CVE-2014-1797", "CVE-2014-1799", "CVE-2014-1800",
                "CVE-2014-1802", "CVE-2014-1803", "CVE-2014-1804", "CVE-2014-1805",
                "CVE-2014-2753", "CVE-2014-2754", "CVE-2014-2755", "CVE-2014-2756",
                "CVE-2014-2757", "CVE-2014-2758", "CVE-2014-2759", "CVE-2014-2760",
                "CVE-2014-2761", "CVE-2014-2763", "CVE-2014-2764", "CVE-2014-2765",
                "CVE-2014-2766", "CVE-2014-2767", "CVE-2014-2768", "CVE-2014-2769",
                "CVE-2014-2770", "CVE-2014-2771", "CVE-2014-2772", "CVE-2014-2773",
                "CVE-2014-2775", "CVE-2014-2776", "CVE-2014-2777");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-11 08:05:23 +0530 (Wed, 11 Jun 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (2969262)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-035.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error when handling CMarkup objects.

  - An error when handling negotiation of certificates during a TLS session.

  - Improper validation of certain permissions.

  - and multiple Unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to conduct session hijacking
  attacks, disclose potentially sensitive information, bypass certain security restrictions, and compromise a user's system.");

  script_tag(name:"affected", value:"Microsoft Internet Explorer version 6.x/7.x/8.x/9.x/10.x/11.x.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2957689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67511");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67518");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67544");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67831");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67833");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67834");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67835");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67836");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67838");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67839");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67840");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67841");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67842");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67843");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67845");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67846");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67847");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67848");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67849");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67850");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67851");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67852");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67854");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67855");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67856");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67857");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67858");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67859");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67860");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67861");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67862");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67863");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67864");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67866");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67867");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67869");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67871");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67872");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67873");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67874");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67875");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67876");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67877");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67878");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67879");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67880");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67881");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67882");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67883");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67884");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67885");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67886");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67887");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67889");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67890");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67891");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67892");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67915");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2963950");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-035");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
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

if(hotfix_check_sp(win2003:3, win2003x64:3, winVista:3, win7:2,
                   win7x64:2, win2008:3, win2008r2:2, win8:1,
                   win8x64:1, win2012:1, win8_1:1, win8_1x64:1) <= 0){
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

if(hotfix_check_sp(win2003:3, win2003x64:3) > 0)
{
  if(version_is_less(version:dllVer, test_version:"6.0.3790.5341") ||
     version_in_range(version:dllVer, test_version:"7.0.6000.00000", test_version2:"7.0.6000.21388")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.23597")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(winVista:3, win2008:3) > 0)
{
  if(version_in_range(version:dllVer, test_version:"7.0.6002.18000", test_version2:"7.0.6002.19097")||
     version_in_range(version:dllVer, test_version:"7.0.6002.22000", test_version2:"7.0.6002.23388")||
     version_in_range(version:dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.19538")||
     version_in_range(version:dllVer, test_version:"8.0.6001.20000", test_version2:"8.0.6001.23597")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16554")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20665")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
{
  if(version_in_range(version:dllVer, test_version:"8.0.7601.16000", test_version2:"8.0.7601.18471")||
     version_in_range(version:dllVer, test_version:"8.0.7601.21000", test_version2:"8.0.7601.22685")||
     version_in_range(version:dllVer, test_version:"9.0.8112.16000", test_version2:"9.0.8112.16554")||
     version_in_range(version:dllVer, test_version:"9.0.8112.20000", test_version2:"9.0.8112.20665")||
     version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16920")||
     version_in_range(version:dllVer, test_version:"10.0.9200.21000", test_version2:"10.0.9200.21043")||
     version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16667")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17125")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8:1, win2012:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"10.0.9200.16000", test_version2:"10.0.9200.16920")||
     version_in_range(version:dllVer, test_version:"10.0.9200.20000", test_version2:"10.0.9200.21043")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

else if(hotfix_check_sp(win8_1:1, win8_1x64:1) > 0)
{
  if(version_in_range(version:dllVer, test_version:"11.0.9600.00000", test_version2:"11.0.9600.16667")||
     version_in_range(version:dllVer, test_version:"11.0.9600.17000", test_version2:"11.0.9600.17125")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}
