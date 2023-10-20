# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804301");
  script_version("2023-07-26T05:05:09+0000");
  script_cve_id("CVE-2014-0494");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:09 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"creation_date", value:"2014-02-03 14:43:16 +0530 (Mon, 03 Feb 2014)");
  script_name("Adobe Digital Edition Denial of Service Vulnerability (Windows)");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The flaw is due to an unspecified error and can be exploited to cause memory
corruption.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to conduct denial of
service or execute an arbitrary code.");
  script_tag(name:"affected", value:"Adobe Digital Edition version 2.0.1 on Windows.");
  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition 3.0 or later.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/56578/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/65091");
  script_xref(name:"URL", value:"http://helpx.adobe.com/security/products/Digital-Editions/apsb14-03.html");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!ediVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_equal(version:ediVer, test_version:"2.0.1"))
{
  report = report_fixed_ver(installed_version:ediVer, vulnerable_range:"Equal to 2.0.1");
  security_message(port:0, data:report);
  exit(0);
}
