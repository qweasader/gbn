# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804391");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2006-3093");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-11 14:22:24 +0530 (Fri, 11 Apr 2014)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities Jun06 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaws exist due to some unspecified errors.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to have unspecified impact.");
  script_tag(name:"affected", value:"Adobe Reader before version 7.0.8 on Mac OS X.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 7.0.8 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/20576");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/18445");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1016314");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/31829");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/327817.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Reader/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"7.0.8")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.0.8");
  security_message(port:0, data:report);
  exit(0);
}
