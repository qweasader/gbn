# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804922");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-29 17:53:43 +0530 (Mon, 29 Sep 2014)");

  script_name("Google Chrome RSA Spoof Vulnerability September14 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to spoof vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"Google Chrome before 37.0.2062.124 on Windows");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version 37.0.2062.124
  or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/09/stable-channel-update-for-chrome-os_24.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70116");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/09/stable-channel-update_24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_chrome_detect_portable_win.nasl");
  script_mandatory_keys("GoogleChrome/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!chromeVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:chromeVer, test_version:"37.0.2062.124"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"37.0.2062.124");
  security_message(port:0, data:report);
  exit(0);
}
