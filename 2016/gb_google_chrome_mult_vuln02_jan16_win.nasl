# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:google:chrome";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806666");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-1612", "CVE-2016-1613", "CVE-2016-1614", "CVE-2016-1615",
                "CVE-2016-1616", "CVE-2016-1617", "CVE-2016-1618", "CVE-2016-1619",
                "CVE-2016-1620", "CVE-2016-2051", "CVE-2016-2052");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-07 18:33:00 +0000 (Wed, 07 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-01-22 14:46:18 +0530 (Fri, 22 Jan 2016)");
  script_name("Google Chrome Multiple Vulnerabilities-02 Jan16 (Windows)");

  script_tag(name:"summary", value:"Google Chrome is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Bad cast in V8.

  - Use-after-free error in PDFium.

  - Information leak error in Blink.

  - Origin confusion error in Omnibox.

  - URL Spoofing.

  - History sniffing with HSTS and CSP.

  - Weak random number generator in Blink.

  - Out-of-bounds read in PDFium.

  - Multiple Other Vulnerabilities.

  - Other Unspecified Vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation would allow a remote
  attacker to conduct URL spoofing attacks, bypass certain security restrictions,
  gain access to sensitive information, cause a denial of service condition or
  possibly have unspecified other impact.");

  script_tag(name:"affected", value:"Google Chrome versions prior to 48.0.2564.82
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Google Chrome version
  48.0.2564.82 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://googlechromereleases.blogspot.in/2016/01/stable-channel-update_20.html");

  script_copyright("Copyright (C) 2016 Greenbone AG");
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

if(version_is_less(version:chromeVer, test_version:"48.0.2564.82"))
{
  report = 'Installed version: ' + chromeVer + '\n' +
           'Fixed version:     48.0.2564.82'  + '\n';
  security_message(data:report);
  exit(0);
}
