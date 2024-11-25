# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:videolan:vlc_media_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902705");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2011-07-29 17:55:33 +0200 (Fri, 29 Jul 2011)");
  script_cve_id("CVE-2011-2588");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player '.AVI' File BOF Vulnerability - Windows");
  script_xref(name:"URL", value:"http://secunia.com/advisories/45066");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48664");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68532");
  script_xref(name:"URL", value:"http://www.videolan.org/security/sa1106.html");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_dependencies("secpod_vlc_media_player_detect_win.nasl");
  script_mandatory_keys("VLCPlayer/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary code in
  the context of the application. Failed attacks will cause denial-of-service
  conditions.");
  script_tag(name:"affected", value:"VLC media player version prior to 1.1.11 on Windows.");
  script_tag(name:"insight", value:"The flaw is due to an integer underflow error when parsing the 'strf'
  chunk within AVI files can be exploited to cause a heap-based buffer
  overflow.");
  script_tag(name:"solution", value:"Upgrade to the VLC media player version 1.1.11 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a buffer overflow vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE )) exit(0);
vers = infos['version'];
path = infos['location'];

if( version_is_less( version:vers, test_version:"1.1.11" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.1.11", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );