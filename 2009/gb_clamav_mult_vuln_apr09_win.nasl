# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800556");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cve_id("CVE-2009-1241", "CVE-2009-1270", "CVE-2008-6680");
  script_name("ClamAV < 0.95 Multiple Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/0934");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34344");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/34357");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2009/04/07/6");
  script_xref(name:"URL", value:"http://blog.zoller.lu/2009/04/clamav-094-and-below-evasion-and-bypass.html");

  script_tag(name:"summary", value:"ClamAV is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Error in handling specially crafted RAR files which prevents the scanning of potentially
  malicious files.

  - Inadequate sanitation of files through a crafted TAR file causes clamd and clamscan to hang.

  - 'libclamav/pe.c' allows remote attackers to cause a denial of service via a crafted EXE which
  triggers a divide-by-zero error.");

  script_tag(name:"impact", value:"Remote attackers may exploit this issue to inject malicious files
  into the system which can bypass the scan engine and may cause denial of service.");

  script_tag(name:"affected", value:"ClamAV before version 0.95.");

  script_tag(name:"solution", value:"Update to version 0.95 or later.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( port:port, cpe:CPE, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];
path = infos["location"];

if( version_is_less( version:vers, test_version:"0.95" ) ){
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.95", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
