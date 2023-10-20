# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804643");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3156", "CVE-2014-3157");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-06-19 11:03:39 +0530 (Thu, 19 Jun 2014)");
  script_name("Google Chrome Multiple Vulnerabilities - 02 June14 (Mac OS X)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaws are due to:

  - A use-after-free error in the 'ChildThread::Shutdown' function in
content/child/child_thread.cc script related to the filesystem API.

  - An out-of-bounds read flaw in SPDY related to reentrancy.

  - An overflow condition related to bitmap handling in the clipboard code.

  - An overflow condition in the 'FFmpegVideoDecoder::GetVideoBuffer' function
in media/filters/ffmpeg_video_decoder.cc script.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct a denial of
service and possibly have other unspecified impact.");
  script_tag(name:"affected", value:"Google Chrome version prior to 35.0.1916.153 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 35.0.1916.153 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58585");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67972");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67977");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67980");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/67981");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/06/stable-channel-update.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_google_chrome_detect_macosx.nasl");
  script_mandatory_keys("GoogleChrome/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"35.0.1916.153"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"35.0.1916.153");
  security_message(port:0, data:report);
  exit(0);
}
