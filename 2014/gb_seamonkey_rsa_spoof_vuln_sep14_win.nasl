# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mozilla:seamonkey";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804921");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-1568");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-29 17:31:10 +0530 (Mon, 29 Sep 2014)");

  script_name("Mozilla Seamonkey RSA Spoof Vulnerability September14 (Windows)");

  script_tag(name:"summary", value:"Mozilla Seamonkey is prone to spoof vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to conduct spoofing attacks.");

  script_tag(name:"affected", value:"Mozilla SeaMonkey before 2.29.1 on Windows");

  script_tag(name:"solution", value:"Upgrade to Mozilla seamonkey version 2.29.1
  or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/61540");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70116");
  script_xref(name:"URL", value:"https://bugzilla.mozilla.org/show_bug.cgi?id=1069405");
  script_xref(name:"URL", value:"https://www.mozilla.org/security/announce/2014/mfsa2014-73.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("gb_seamonkey_detect_win.nasl");
  script_mandatory_keys("Seamonkey/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!smVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:smVer, test_version: "2.29.1"))
{
  report = report_fixed_ver(installed_version:smVer, fixed_version:"2.29.1");
  security_message(port:0, data:report);
  exit(0);
}
