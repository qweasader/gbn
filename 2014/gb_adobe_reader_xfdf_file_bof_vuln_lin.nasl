# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804389");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2004-0194");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-10 15:10:46 +0530 (Thu, 10 Apr 2014)");
  script_name("Adobe Reader 'XFDF' File Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"Adobe Reader is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to the boundary error in 'OutputDebugString' function.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code on
the system and gain sensitive information.");
  script_tag(name:"affected", value:"Adobe Reader version 5.1 on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 6.0 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/15384");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/9802");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17488/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!readerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(readerVer && readerVer =~ "^5")
{
  if(version_is_equal(version:readerVer, test_version:"5.1"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
