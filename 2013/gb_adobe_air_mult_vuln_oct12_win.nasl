# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803451");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-5248", "CVE-2012-5249", "CVE-2012-5250", "CVE-2012-5251",
                "CVE-2012-5252", "CVE-2012-5253", "CVE-2012-5254", "CVE-2012-5255",
                "CVE-2012-5256", "CVE-2012-5257", "CVE-2012-5258", "CVE-2012-5259",
                "CVE-2012-5260", "CVE-2012-5261", "CVE-2012-5262", "CVE-2012-5263",
                "CVE-2012-5264", "CVE-2012-5265", "CVE-2012-5266", "CVE-2012-5267",
                "CVE-2012-5268", "CVE-2012-5269", "CVE-2012-5270", "CVE-2012-5271",
                "CVE-2012-5272", "CVE-2012-5673", "CVE-2012-5285", "CVE-2012-5286",
                "CVE-2012-5287");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-03-28 13:10:53 +0530 (Thu, 28 Mar 2013)");
  script_name("Adobe Air Multiple Vulnerabilities - October 12 (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50876/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56374");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56375");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56376");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56377");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-22.html");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("Adobe/Air/Win/Installed");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code on the target system or cause a denial of service (memory corruption)
  via unspecified vectors.");
  script_tag(name:"affected", value:"Adobe AIR version 3.4.0.2540 and earlier on Windows");
  script_tag(name:"insight", value:"The flaws are due to memory corruption, buffer overflow errors that
  could lead to code execution.");
  script_tag(name:"solution", value:"Update to Adobe Air version 3.4.0.2710 or later.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"Adobe Air is prone to multiple vulnerabilities.");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if( version_is_less_equal( version:vers, test_version:"3.4.0.2540" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.4.0.2710", install_path:path );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );
