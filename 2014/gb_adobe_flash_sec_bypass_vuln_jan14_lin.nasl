# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804065");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-21 11:10:22 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe Flash Player Security Bypass Vulnerability Jan14 (Linux)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an unspecified error and other additional weakness.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, bypass certain security
restrictions and disclose certain memory information.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 11.2.202.335 on Linux.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.2.202.335 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64810");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"11.2.202.335"))
{
  report = report_fixed_ver(installed_version:playerVer, fixed_version:"11.2.202.335");
  security_message(port:0, data:report);
  exit(0);
}
