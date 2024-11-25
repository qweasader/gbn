# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814760");
  script_version("2024-02-21T05:06:27+0000");
  script_cve_id("CVE-2019-0657");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-21 05:06:27 +0000 (Wed, 21 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-07 16:55:00 +0000 (Thu, 07 Mar 2019)");
  script_tag(name:"creation_date", value:"2019-02-26 15:47:32 +0530 (Tue, 26 Feb 2019)");
  script_name(".NET Core Domain Spoofing Vulnerability (Feb 2019)");

  script_tag(name:"summary", value:"'System.Private.Uri' or 'Microsoft.NETCore.App' package is prone to domain spoofing vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to an error in .Net
  Framework API's in the way they parse URL's.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"System.Private.Uri package with version 4.3.0
  and Microsoft.NETCore.App package with versions 2.1.x prior to 2.1.8, 2.2.x prior
  to 2.2.2");

  script_tag(name:"solution", value:"Upgrade toSystem.Private.Uri package to
  version 4.3.1 or later. Upgrade Microsoft.NETCore.App package to versions
  2.1.8 or 2.2.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"https://github.com/dotnet/announcements/issues/97");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/106890");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2019-0657");

  script_copyright("Copyright (C) 2019 Greenbone AG");
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

if( get_kb_item( "win/lsc/disable_wmi_search" ) )
  exit( 0 );

infos = kb_smb_wmi_connectinfo();
if( ! infos )
  exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle )
  exit( 0 );

fileList = wmi_file_file_search( handle:handle, fileName:"System.Private.Uri", includeHeader:TRUE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) )
  exit( 0 );

report = "";  # nb: To make openvas-nasl-lint happy...

foreach filePath( fileList )
{
  if( eregmatch( pattern:".*system.private.uri.4.3.0", string:filePath))
  {
    VULN = TRUE;
    report += report_fixed_ver( file_version:"4.3.0", file_checked:filePath, fixed_version:"4.3.1" ) + '\n';
  }
}

if( VULN )
{
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
