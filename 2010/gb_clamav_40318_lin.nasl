# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100656");
  script_version("2023-07-28T16:09:07+0000");
  script_tag(name:"last_modification", value:"2023-07-28 16:09:07 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2010-05-25 18:01:00 +0200 (Tue, 25 May 2010)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_cve_id("CVE-2010-1640");
  script_name("ClamAV < 0.96.1 'parseicon()' DoS Vulnerability - Linux");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_remote_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("clamav/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/40318");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blobdiff;f=libclamav/pe_icons.c;h=3f1bc5be69d0f9d84e576814d1a3cc6f40c4ff2c;hp=39a714f05968f9e929576bf171dd0eb58bf06bef;hb=7f0e3bbf77382d9782e0189bf80f");
  script_xref(name:"URL", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2031");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=blob_plain;f=ChangeLog;hb=clamav-0.96.1");
  script_xref(name:"URL", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/2940");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"summary", value:"ClamAV is prone to a vulnerability that attackers can exploit
  to cause denial-of-service conditions.");

  script_tag(name:"affected", value:"ClamAV 0.96 is vulnerable.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

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

if( version_is_less( version:vers, test_version:"0.96.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.96.1", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
