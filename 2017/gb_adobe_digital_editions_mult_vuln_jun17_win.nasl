# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811116");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-3088", "CVE-2017-3089", "CVE-2017-3093", "CVE-2017-3096",
                "CVE-2017-3090", "CVE-2017-3092", "CVE-2017-3097", "CVE-2017-3094",
                "CVE-2017-3095");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-06-20 10:45:13 +0530 (Tue, 20 Jun 2017)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Adobe Digital Editions Multiple Vulnerabilities Jun17 (Windows)");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A memory corruption error.

  - Multiple insecure library loading errors.

  - A stack overflow error.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges
  and disclose sensitive information.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.5
  on Windows.");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.5 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb17-20.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99024");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99021");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_win.nasl");
  script_mandatory_keys("AdobeDigitalEdition/Win/Ver");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:digitalVer, test_version:"4.5.5"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.5");
  security_message(data:report);
  exit(0);
}
