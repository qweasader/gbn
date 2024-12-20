# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813674");
  script_version("2024-02-20T05:05:48+0000");
  script_cve_id("CVE-2018-8171");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-20 05:05:48 +0000 (Tue, 20 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-09-10 18:53:00 +0000 (Mon, 10 Sep 2018)");
  script_tag(name:"creation_date", value:"2018-07-13 15:50:36 +0530 (Fri, 13 Jul 2018)");
  script_name("Microsoft ASP.NET Core Security Feature Bypass Vulnerability (Jul 2018)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (CVE-2018-8171).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists because system does not properly
  validate the number of incorrect login attempts.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to bypass security controls on the target system.");

  script_tag(name:"affected", value:"Any ASP.NET Core based application that uses
  'Microsoft.AspNetCore.Identity' with versions 1.0.0, 1.0.1, 1.0.2, 1.0.3, 1.0.4,
  1.0.5. 1.1.0, 1.1.1, 1.1.2, 1.1.3, 1.1.4, 1.1.5, 2.0.0, 2.0.1, 2.0.2, 2.0.3,
  2.1.0, 2.1.1.");

  script_tag(name:"solution", value:"Upgrade 'Microsoft.AspNetCore.Identity' package
  versions to 1.0.6 or 1.1.6 or 2.0.4 or 2.1.2 or later. Please see the references
  for more info.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8171");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/104659");
  script_xref(name:"URL", value:"https://github.com/aspnet/announcements/issues/310");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("WMI/access_successful", "SMB/WindowsVersion");
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path
fileList = wmi_file_fileversion( handle:handle, fileName:"Microsoft.AspNetCore.Identity", fileExtn:"dll", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_in_range( version:version[1], test_version:"1.0", test_version2:"1.0.5" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.0.6" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"1.1", test_version2:"1.1.5" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"1.1.6" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"2.0", test_version2:"2.0.3" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"2.0.4" ) + '\n';
    } else if( version_in_range( version:version[1], test_version:"2.1", test_version2:"2.1.1" ) ) {
      VULN = TRUE;
      report += report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"2.1.2" ) + '\n';
    }
  }
}

if( VULN ) {
  security_message( port:0, data:report );
  exit( 99 );
}

exit( 99 );
