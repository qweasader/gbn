# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:sharepoint_designer";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804586");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0251");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-05-14 16:25:28 +0530 (Wed, 14 May 2014)");
  script_name("Microsoft SharePoint Designer Multiple Vulnerabilities (2952166)");

  script_tag(name:"summary", value:"This host is missing a critical security update according to Microsoft
  Bulletin MS14-022.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaws is due to multiple unspecified components when handling page content.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute the arbitrary
  code and compromise a vulnerable system.");

  script_tag(name:"affected", value:"- Microsoft SharePoint Designer 2007 Service Pack 3 and prior

  - Microsoft SharePoint Designer 2010 Service Pack 2 and prior

  - Microsoft SharePoint Designer 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-022");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67283");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_dependencies("gb_sharepoint_designer_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/SharePoint/Designer/Ver");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
designVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## SharePoint Designer 2010
if(designVer =~ "^14\.")
{
  dllVer = fetch_file_version(sysPath:path, file_name:"\Office14\Microsoft.web.design.client.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7115.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## SharePoint Designer 2013
if(designVer =~ "^15\.")
{
  dllVer2 = fetch_file_version(sysPath:path, file_name:"\Office15\1033\Fpexpsat.dll");
  if(dllVer2)
  {
    if(version_in_range(version:dllVer2, test_version:"15.0", test_version2:"15.0.4567.999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);