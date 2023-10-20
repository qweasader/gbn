# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804841");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-0559", "CVE-2014-0557", "CVE-2014-0556", "CVE-2014-0555",
                "CVE-2014-0553", "CVE-2014-0552", "CVE-2014-0551", "CVE-2014-0550",
                "CVE-2014-0549", "CVE-2014-0548", "CVE-2014-0547", "CVE-2014-0554");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-12 11:27:48 +0530 (Fri, 12 Sep 2014)");

  script_name("Adobe Flash Player Multiple Vulnerabilities-01 Sep14 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to multiple
  unspecified errors and an use-after-free error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to disclose potentially sensitive information and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Flash Player version before
  13.0.0.244, 14.x and 15.x before 15.0.0.152 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.244 or 15.0.0.152 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60985");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69695");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69696");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69699");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69700");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69701");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69702");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69703");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69704");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69705");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69706");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69707");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-21.html");

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

if(version_is_less(version:playerVer, test_version:"13.0.0.244") ||
   version_in_range(version:playerVer, test_version:"14.0.0", test_version2:"15.0.0.151"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
