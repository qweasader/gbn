# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803898");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2013-5324", "CVE-2013-3361", "CVE-2013-3362", "CVE-2013-3363");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-09-18 18:49:10 +0530 (Wed, 18 Sep 2013)");
  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Sep13 (Mac OS X)");


  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 11.7.700.242 or 11.8.800.168 or later.");
  script_tag(name:"insight", value:"Flaws are due to multiple unspecified errors.");
  script_tag(name:"affected", value:"Adobe Flash Player before 11.7.700.242 and 11.8.x before 11.8.800.168 on
Mac OS X");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code, cause
memory corruption and compromise a user's system.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/54697/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62294");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62295");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/62296");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/bulletins/apsb13-21.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
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

if(version_is_less(version:playerVer, test_version:"11.7.700.242") ||
   version_in_range(version:playerVer, test_version:"11.8.0", test_version2:"11.8.800.167"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
