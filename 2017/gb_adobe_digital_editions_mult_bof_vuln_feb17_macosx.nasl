# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:digital_editions";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.810601");
  script_version("2024-02-09T05:06:25+0000");
  script_cve_id("CVE-2017-2973", "CVE-2017-2974", "CVE-2017-2975", "CVE-2017-2976",
                "CVE-2017-2977", "CVE-2017-2978", "CVE-2017-2979", "CVE-2017-2980",
                "CVE-2017-2981");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-09 05:06:25 +0000 (Fri, 09 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-25 01:29:00 +0000 (Tue, 25 Jul 2017)");
  script_tag(name:"creation_date", value:"2017-02-15 09:38:58 +0530 (Wed, 15 Feb 2017)");
  script_tag(name:"qod_type", value:"executable_version");
  script_name("Adobe Digital Editions Multiple Buffer Overflow Vulnerabilities (Feb 2017) - Mac OS X");

  script_tag(name:"summary", value:"Adobe Digital Edition is prone to multiple buffer overflow vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - A heap buffer overflow error.

  - Multiple memory leak errors.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to trigger a buffer overflow and execute arbitrary code on the
  target system. Also buffer overflow could lead to a memory leak.");

  script_tag(name:"affected", value:"Adobe Digital Edition prior to 4.5.4 on
  Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Adobe Digital Edition version
  4.5.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1037816");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/Digital-Editions/apsb17-05.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_digital_edition_detect_macosx.nasl");
  script_mandatory_keys("AdobeDigitalEdition/MacOSX/Version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!digitalVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:digitalVer, test_version:"4.5.4"))
{
  report = report_fixed_ver(installed_version:digitalVer, fixed_version:"4.5.4");
  security_message(data:report);
  exit(0);
}
