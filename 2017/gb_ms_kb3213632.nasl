# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811749");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2017-8742", "CVE-2017-8696");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-09-29 18:58:00 +0000 (Fri, 29 Sep 2017)");
  script_tag(name:"creation_date", value:"2017-09-13 10:49:10 +0530 (Wed, 13 Sep 2017)");
  script_name("Microsoft Office Web Apps 2010 Service Pack 2 Multiple Vulnerabilities (KB3213632)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft KB3213632.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an error in Microsoft Office
  because it fails to properly handle objects in memory and due to the way Windows Uniscribe
  handles objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to run arbitrary code in the context
  of the current user and take control of the affected system.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3213632");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100741");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100780");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_web_apps_detect.nasl");
  script_mandatory_keys("MS/Office/Web/Apps/Ver");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if( ! infos = get_app_version_and_location( cpe:"cpe:/a:microsoft:office_web_apps", exit_no_version:TRUE ) ) exit( 0 );
webappVer = infos['version'];
path = infos['location'];
if(!path || "Could not find the install location" >< path){
  exit(0);
}

## Microsoft Office Web Apps 2010
if(webappVer =~ "^14\.")
{
  path = path + "\PPTConversionService\bin\Converter";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7188.4999"))
    {
      report = 'File checked:     ' +  path + "\msoserver.dll" + '\n' +
               'File version:     ' +  dllVer  + '\n' +
               'Vulnerable range: ' +  "14.0 - 14.0.7188.4999" + '\n' ;
      security_message(data:report);
      exit(0);
    }
  }
}

exit(99);
