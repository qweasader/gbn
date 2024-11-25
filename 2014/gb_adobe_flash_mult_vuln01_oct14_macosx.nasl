# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805003");
  script_version("2024-02-09T14:47:30+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2014-0558", "CVE-2014-0564", "CVE-2014-0569", "CVE-2014-8439");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 14:47:30 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-10-20 12:40:11 +0530 (Mon, 20 Oct 2014)");

  script_name("Adobe Flash Player Multiple Vulnerabilities (APSB14-22) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Two unspecified errors can be exploited to corrupt memory and subsequently
    execute arbitrary code.

  - An integer overflow error can be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  13.0.0.250 and 14.x and 15.x before 15.0.0.189 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.250 or 15.0.0.189 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://secunia.com/advisories/59729");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70437");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70441");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70442");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71289");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-22.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.250") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"15.0.0.188"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
