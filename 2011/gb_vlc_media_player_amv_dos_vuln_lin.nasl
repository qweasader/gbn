# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802118");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_cve_id("CVE-2011-1931");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("VLC Media Player 'AMV' Denial of Service Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/517706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47602");
  script_xref(name:"URL", value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=624339");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("secpod_vlc_media_player_detect_lin.nasl");
  script_mandatory_keys("VLCPlayer/Lin/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause a denial
of service or possibly execute arbitrary code via a malformed AMV file.");
  script_tag(name:"affected", value:"VLC media player version 1.1.9 and prior on Linux.");
  script_tag(name:"insight", value:"The flaw is due to error while handling 'sp5xdec.c' in the
Sunplus SP5X JPEG decoder in libavcodec, performs a write operation outside the
bounds of an unspecified array.");
  script_tag(name:"solution", value:"Upgrade to VLC media player version 1.1.10 or later.");
  script_tag(name:"summary", value:"VLC Media Player is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vlcVer = get_kb_item("VLCPlayer/Lin/Ver");
if(!vlcVer){
  exit(0);
}

if(version_is_less_equal(version:vlcVer, test_version:"1.1.9")){
  report = report_fixed_ver(installed_version:vlcVer, vulnerable_range:"Less than or equal to 1.1.9");
  security_message(port: 0, data: report);
}
