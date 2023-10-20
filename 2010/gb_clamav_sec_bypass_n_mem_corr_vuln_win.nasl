# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801311");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-04-13 16:55:19 +0200 (Tue, 13 Apr 2010)");
  script_cve_id("CVE-2010-0098", "CVE-2010-1311");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("ClamAV < 0.96 Security Bypass And Memory Corruption Vulnerabilities - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("General");
  script_dependencies("gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"http://secunia.com/advisories/39329");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/39262");
  script_xref(name:"URL", value:"http://en.securitylab.ru/nvd/392749.php");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96");

  script_tag(name:"summary", value:"ClamAV is prone to security bypass and memory corruption
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to:

  - An error in handling of 'CAB' and '7z' file formats, which allows to bypass virus detection via
  a crafted archive that is compatible with standard archive utilities.

  - An error in 'qtm_decompress' function in 'libclamav/mspack.c', which allows to crash application
  via a crafted CAB archive that uses the Quantum.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain
  security restrictions.");

  script_tag(name:"affected", value:"ClamAV versions before 0.96 (1.0.26).");

  script_tag(name:"solution", value:"Update to version 0.96 or later.");

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

if( version_is_less( version:vers, test_version:"0.96" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.96", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );