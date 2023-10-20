# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804339");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-1700", "CVE-2014-1701", "CVE-2014-1702", "CVE-2014-1703",
                "CVE-2014-1704");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-03-19 12:49:04 +0530 (Wed, 19 Mar 2014)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Mar2014 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A use-after-free error within 'modules/speech/SpeechSynthesis.cpp' in blink.

  - Insufficient cross-origin restriction within 'GenerateFunction' function in
  blink.

  - A use-after-free error within 'DatabaseThread::cleanupDatabaseThread'
  function in web database in blink.

  - A use-after-free error within 'WebSocketDispatcherHost::SendOrDrop' function
  in web sockets implementation.

  - More unspecified errors within v8.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to disclose potentially
sensitive information, conduct cross-site scripting attacks, conduct denial
of service, bypass certain security restrictions and possibly unspecified
other impacts.");
  script_tag(name:"affected", value:"Google Chrome version prior to 33.0.1750.149 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Google Chrome 33.0.1750.149 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57164");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66120");
  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2014/03/stable-channel-update_11.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
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

if(version_is_less(version:chromeVer, test_version:"33.0.1750.149"))
{
  report = report_fixed_ver(installed_version:chromeVer, fixed_version:"33.0.1750.149");
  security_message(port:0, data:report);
  exit(0);
}
