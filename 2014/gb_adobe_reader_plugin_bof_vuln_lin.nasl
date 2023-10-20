# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804259");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2005-2470");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-04-15 19:10:55 +0530 (Tue, 15 Apr 2014)");
  script_name("Adobe Reader 'Plug-in' Buffer Overflow Vulnerability (Linux)");

  script_tag(name:"summary", value:"Adobe Reader is prone to a buffer overflow vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw exists due to an unspecified boundary error in the core application
plug-in.");
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to conduct denial of service and
possibly execute arbitrary code.");
  script_tag(name:"affected", value:"Adobe Reader version 7.0 and prior on Linux.");
  script_tag(name:"solution", value:"Upgrade to Adobe Reader 7.0.1 or later.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/16466");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/14603");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1014712");
  script_xref(name:"URL", value:"http://www.adobe.com/support/techdocs/321644.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Reader/Linux/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!vers = get_app_version(cpe:CPE))
  exit(0);

if(vers && vers =~ "^7\.") {
  if(version_is_less_equal(version:vers, test_version:"7.0"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
