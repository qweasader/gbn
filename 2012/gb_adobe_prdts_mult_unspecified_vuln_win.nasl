# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802954");
  script_version("2023-05-04T09:51:03+0000");
  script_cve_id("CVE-2012-4363");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-04 09:51:03 +0000 (Thu, 04 May 2023)");
  script_tag(name:"creation_date", value:"2012-08-24 16:05:37 +0530 (Fri, 24 Aug 2012)");
  script_name("Adobe Reader Multiple Unspecified Vulnerabilities (Aug 2012) - Windows");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_win.nasl");
  script_mandatory_keys("Adobe/Reader/Win/Installed");

  script_xref(name:"URL", value:"http://secunia.com/advisories/50290");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55055");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple unspecified
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaws are due to an unspecified errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary
  code in the context of the affected application.");

  script_tag(name:"affected", value:"Adobe Reader versions 9.x through 9.5.2 and 10.x through
  10.1.4 on Windows.");

  script_tag(name:"solution", value:"Update to version 9.5.3, 10.1.5 or later.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(version_is_less(version:vers, test_version:"9.5.3") ||
   version_in_range(version:vers, test_version:"10.0", test_version2:"10.1.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.5.3/10.1.5");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
