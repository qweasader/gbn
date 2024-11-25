# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.809088");
  script_version("2024-11-22T15:40:47+0000");
  script_cve_id("CVE-2014-7136");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2016-11-07 14:25:26 +0530 (Mon, 07 Nov 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("K7Firewall < 14.0.1.16 Packet Driver Privilege Escalation Vulnerability");

  script_tag(name:"summary", value:"K7 Computing product is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to the function handling
  IOCTL 0x830020C4 does not validate the size of the output buffer parameter
  passed in the DeviceIoControl API, which leads to a heap overflow on buffer
  data initialization.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  allows local users to execute arbitrary code with kernel privileges.");

  script_tag(name:"affected", value:"K7Firewall Packet Driver version 11.0.1.5
  and possibly earlier.");

  script_tag(name:"solution", value:"Upgrade to K7Firewall Packet Driver
  version 14.0.1.16 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/129474");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71611");
  script_xref(name:"URL", value:"https://www.portcullis-security.com/security-research-and-downloads/security-advisories/cve-2014-7136");

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Privilege escalation");
  script_dependencies("smb_reg_service_pack.nasl", "gb_wmi_access.nasl", "lsc_options.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "WMI/access_successful");
  script_require_ports(139, 445);
  script_exclude_keys("win/lsc/disable_wmi_search");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("wmi_file.inc");
include("list_array_func.inc");

if( ! registry_key_exists( key:"SOFTWARE\K7 Computing" ) &&
    ! registry_key_exists( key:"SOFTWARE\Wow6432Node\K7 Computing" ) ) {
  exit( 0 );
}

infos = kb_smb_wmi_connectinfo();
if( ! infos ) exit( 0 );

handle = wmi_connect( host:infos["host"], username:infos["username_wmi_smb"], password:infos["password"] );
if( ! handle ) exit( 0 );

# TODO: Limit to a possible known common path
fileList = wmi_file_fileversion( handle:handle, fileName:"K7FWFilt", fileExtn:"sys", includeHeader:FALSE );
wmi_close( wmi_handle:handle );
if( ! fileList || ! is_array( fileList ) ) {
  exit( 0 );
}

foreach filePath( keys( fileList ) ) {

  vers = fileList[filePath];

  if( vers && version = eregmatch( string:vers, pattern:"^([0-9.]+)" ) ) {

    if( version_is_less( version:version[1], test_version:"14.0.1.16" ) ) {
      report = report_fixed_ver( file_version:version[1], file_checked:filePath, fixed_version:"14.0.1.16" );
      security_message( port:0, data:report );
      exit( 0 );
    }
  }
}

exit( 99 );
