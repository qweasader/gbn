# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:microsoft:office_web_apps";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805165");
  script_version("2024-07-25T05:05:41+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-1641", "CVE-2015-1649", "CVE-2015-1650");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-07-25 05:05:41 +0000 (Thu, 25 Jul 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-07-24 17:06:41 +0000 (Wed, 24 Jul 2024)");
  script_tag(name:"creation_date", value:"2015-04-15 14:18:05 +0530 (Wed, 15 Apr 2015)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Microsoft Office Web Apps Multiple Vulnerabilities (3048019)");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Bulletin MS15-033.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper handling of memory
  objects while parsing specially crafted Office files.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to corrupt system memory in such a way as to allow an attacker to
  execute arbitrary code.");

  script_tag(name:"affected", value:"Microsoft Office Web Apps Server 2013 Service Pack 1 and Microsoft Office Web Apps Server 2010 Service Pack 2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965238");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/2965306");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/MS15-033");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

if(webappVer =~ "^14\..*")
{
  ## Microsoft Office Web Apps 2010
  dllVer = fetch_file_version(sysPath:path,
           file_name:"\14.0\WebServices\ConversionService\Bin\Converter\sword.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7147.4999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

## Microsoft Office Web Apps 2013
if(webappVer =~ "^15\..*")
{
  path = path + "\PPTConversionService\bin\Converter\";

  dllVer = fetch_file_version(sysPath:path, file_name:"msoserver.dll");
  if(dllVer)
  {
    if(version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4711.999"))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

exit(99);