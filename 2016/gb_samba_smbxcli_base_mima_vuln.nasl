# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:samba:samba";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807345");
  script_version("2023-07-21T05:05:22+0000");
  script_cve_id("CVE-2016-2119");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-29 20:20:00 +0000 (Mon, 29 Aug 2022)");
  script_tag(name:"creation_date", value:"2016-07-12 12:51:22 +0530 (Tue, 12 Jul 2016)");
  script_name("Samba 'libcli/smb/smbXcli_base.c' Man In The Middle (MIMA) Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("smb_nativelanman.nasl", "gb_samba_detect.nasl");
  script_mandatory_keys("samba/smb_or_ssh/detected");

  script_xref(name:"URL", value:"https://www.samba.org/samba/security/CVE-2016-2119.html");
  script_xref(name:"URL", value:"https://access.redhat.com/security/cve/cve-2016-2119");

  script_tag(name:"summary", value:"Samba is prone to a man-in-the-middle (MITM) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in the way DCE/RPC
  connections are initiated by the user. Any authenticated DCE/RPC connection
  that a client initiates against the server could be use by a man-in-the middle
  attacker to impersonate the server by injecting the SMB2_SESSION_FLAG_IS_GUEST
  or SMB2_SESSION_FLAG_IS_NULL flag.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to bypass a client-signing protection mechanism, and consequently
  spoof SMB2 and SMB3 servers.");

  script_tag(name:"affected", value:"Samba versions 4.x before 4.2.14,
  4.3.x before 4.3.11, and 4.4.x before 4.4.5.");

  script_tag(name:"solution", value:"Upgrade to Samba version 4.2.14
  or 4.3.11 or 4.4.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
loc = infos['location'];

if( version_in_range( version:vers, test_version:"4.0.0", test_version2:"4.2.13" ) ) {
  fix = "4.2.14";
  VULN = TRUE ;
} else if( version_in_range( version:vers, test_version:"4.3.0", test_version2:"4.3.10" ) ) {
  fix = "4.3.11";
  VULN = TRUE ;
} else if( version_in_range( version:vers, test_version:"4.4.0", test_version2:"4.4.4" ) ) {
  fix = "4.4.5";
  VULN = TRUE ;
}

if( VULN ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:fix, install_path:loc );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );