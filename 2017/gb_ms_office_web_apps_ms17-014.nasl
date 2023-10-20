# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810712");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-0020", "CVE-2017-0030", "CVE-2017-0105");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-03-15 14:24:41 +0530 (Wed, 15 Mar 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps Multiple Vulnerabilities (4013241)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS17-014");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists as,

  - Office software fails to properly handle objects in memory.

  - Office or Word reads out of bound memory due to an uninitialized variable.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code in the context of the currently logged-in
  user and gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"- Microsoft Office Web Apps 2010 Service Pack 2 and prior

  - Microsoft Office Web Apps Server 2013 Service Pack 1 and prior");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3178689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96050");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96051");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96746");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3172457/");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS17-014");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## Microsoft Office Web Apps 2010 and 2013
if(webappVer =~ "^(14|15)\..*")
{
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7179.4999"))
    {
     report = 'File checked:     ' +  path + "14.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
              'File version:     ' + dllVer  + '\n' +
              'Vulnerable range: ' + "14.0 - 14.0.7179.4999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }

  dllVer1 = fetch_file_version(sysPath:path,
           file_name:"\15.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer1)
  {
    if(version_in_range(version:dllVer1, test_version:"15.0", test_version2:"15.0.4911.0999"))
    {
      report = 'File checked:     ' +  path + "15.0\WebServices\ConversionService\Bin\Converter\sword.dll" + '\n' +
               'File version:     ' + dllVer1  + '\n' +
               'Vulnerable range: ' + "15.0 - 15.0.4911.0999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
