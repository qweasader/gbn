# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803900");
  script_version("2024-02-08T14:36:53+0000");
  script_cve_id("CVE-2013-1868", "CVE-2012-5855");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-08 14:36:53 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2013-07-16 14:24:20 +0530 (Tue, 16 Jul 2013)");
  script_name("VLC Media Player Multiple Vulnerabilities (Jul 2013) - Windows");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to overflow buffer, cause denial
of service or potentially execution of arbitrary code.");
  script_tag(name:"affected", value:"VLC media player version 2.0.4 and prior on Windows");
  script_tag(name:"insight", value:"Multiple flaws due to:

  - Error in 'SHAddToRecentDocs()' function.

  - Error due to improper validation of user supplied inputs when handling
   HTML subtitle files.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 2.0.5 or later.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"summary", value:"VLC Media Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/79823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56405");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/57079");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less_equal( version:vers, test_version:"2.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.5", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
