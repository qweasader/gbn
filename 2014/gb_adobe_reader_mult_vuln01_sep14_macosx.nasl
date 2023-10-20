# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:acrobat_reader";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804487");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0560", "CVE-2014-0561", "CVE-2014-0563", "CVE-2014-0565",
                "CVE-2014-0566", "CVE-2014-0567", "CVE-2014-0568", "CVE-2014-0562");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-09-19 13:57:48 +0530 (Fri, 19 Sep 2014)");

  script_name("Adobe Reader Multiple Vulnerabilities-01 Sep14 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Reader is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An use-after-free error can be exploited to execute arbitrary code.

  - An unspecified error can be exploited to conduct cross-site scripting
    attacks.

  - An error within the implementation of the 'replace()' JavaScript function
    can be exploited to cause a heap-based buffer overflow via specially crafted
    arguments.

  - An error within the 3DIF Plugin (3difr.x3d) can be exploited to cause
    a heap-based buffer overflow via a specially crafted PDF file.

  - Some unspecified errors can be exploited to cause a memory corruption.

  - An unspecified error can be exploited to bypass certain sandbox
    restrictions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to disclose potentially sensitive information, bypass certain
  security restrictions, execute arbitrary code and compromise a user's system.");

  script_tag(name:"affected", value:"Adobe Reader 10.x before 10.1.12 and
  11.x before 11.0.09 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Reader version 10.1.12 or
  11.0.09 or later.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/60901");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69821");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69822");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69823");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69824");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69825");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69826");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69827");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/69828");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/reader/apsb14-20.html");
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

if(vers && vers =~ "^1[01]\.") {
  if(version_in_range(version:vers, test_version:"10.0.0", test_version2:"10.1.11")||
     version_in_range(version:vers, test_version:"11.0.0", test_version2:"11.0.08"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}
