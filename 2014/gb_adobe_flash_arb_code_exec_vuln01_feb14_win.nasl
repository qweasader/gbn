# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804085");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0497");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-05 15:02:43 +0530 (Wed, 05 Feb 2014)");
  script_name("Adobe Flash Player Arbitrary Code Execution Vulnerability - 01 Feb14 (Windows)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an arbitrary code execution vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an integer underflow condition that is triggered as unspecified
user-supplied input is not properly validated.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, execute arbitrary code and
cause buffer overflow.");
  script_tag(name:"affected", value:"Adobe Flash Player versions before 11.7.700.261 and 11.8.x through 12.0.x
before 12.0.0.44 on Windows");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.261 or 12.0.0.44 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56737");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65327");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-04.html");
  script_xref(name:"URL", value:"http://krebsonsecurity.com/2014/02/adobe-pushes-fix-for-flash-zero-day-attack");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_win.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Win/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.7.700.261") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"12.0.0.43"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
