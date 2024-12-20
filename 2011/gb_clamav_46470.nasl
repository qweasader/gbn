# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:clamav:clamav";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103083");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-02-22 13:26:53 +0100 (Tue, 22 Feb 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2011-1003");
  script_name("ClamAV < 0.97 'vba_read_project_strings()' Double Free Memory Corruption Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("gb_clamav_ssh_login_detect.nasl", "gb_clamav_smb_login_detect.nasl", "gb_clamav_remote_detect.nasl");
  script_mandatory_keys("clamav/detected");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/46470");
  script_xref(name:"URL", value:"https://wwws.clamav.net/bugzilla/show_bug.cgi?id=2486");
  script_xref(name:"URL", value:"http://git.clamav.net/gitweb?p=clamav-devel.git;a=commitdiff;h=d21fb8d975f8c9688894a8cef4d50d977022e09f");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more
  information.");

  script_tag(name:"summary", value:"ClamAV is prone to a double-free memory-corruption
  vulnerability.");

  script_tag(name:"affected", value:"ClamAV prior to version 0.97.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to cause denial-of-service
  conditions. Due to the nature of this issue, arbitrary code execution may be possible. This has
  not been confirmed.");

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

if( version_is_less( version:vers, test_version:"0.97" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.97", install_path:path );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
