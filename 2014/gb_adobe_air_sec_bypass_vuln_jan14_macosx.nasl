# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:adobe_air";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804067");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2014-0491", "CVE-2014-0492");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-01-21 11:23:13 +0530 (Tue, 21 Jan 2014)");
  script_name("Adobe AIR Security Bypass Vulnerability Jan14 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe AIR is prone to a security bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an unspecified error and other additional weakness.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to, bypass certain security
restrictions and disclose certain memory information.");
  script_tag(name:"affected", value:"Adobe AIR version before 4.0.0.1390 on Mac OS X.");
  script_tag(name:"solution", value:"Update to Adobe AIR version 4.0.0.1390 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56267");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64810");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/flash-player/apsb14-02.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Air/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"4.0.0.1390")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.0.1390");
  security_message(port:0, data:report);
  exit(0);
}
