# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804515");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2014-0503", "CVE-2014-0504");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"creation_date", value:"2014-03-20 10:50:26 +0530 (Thu, 20 Mar 2014)");
  script_name("Adobe Flash Player Multiple Security Bypass Vulnerabilities - 01 (Feb 2014) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple security bypass vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw are due to multiple unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to bypass certain security
restrictions and disclose potentially sensitive information.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.7.700.272 and 11.8.x through 12.0.x
before 12.0.0.77 on Mac OS X");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.272 or 12.0.0.77 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/57271");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66122");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/66127");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-08.html");
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

if(version_is_less(version:playerVer, test_version:"11.7.700.272") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"12.0.0.76"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
