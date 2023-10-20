# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100830");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-09-29 12:56:18 +0200 (Wed, 29 Sep 2010)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2010-3434");
  script_name("ClamAV < 0.96.3 'find_stream_bounds()' PDF File Processing DoS Vulnerability - Windows");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_windows");

  script_xref(name:"URL", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2226");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.3");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/43555");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=dc5143b4669ae39c79c9af50d569c28c798f33da");
  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/3547");

  script_tag(name:"summary", value:"ClamAV is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  code on the system with clamd privileges or cause the application to crash.");

  script_tag(name:"affected", value:"ClamAV versions before 0.96.3.");

  script_tag(name:"insight", value:"The flaw exists due to a buffer overflow error in
  'find_stream_bounds()' function in 'pdf.c' file within the libclamav.");

  script_tag(name:"solution", value:"Update to version 0.96.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

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

if( version_is_less( version:vers, test_version:"0.96.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
