# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900807");
  script_version("2023-05-17T09:09:49+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2009-1862");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-05-17 09:09:49 +0000 (Wed, 17 May 2023)");
  script_tag(name:"creation_date", value:"2009-07-29 08:47:44 +0200 (Wed, 29 Jul 2009)");

  script_name("Adobe Products '.pdf' and '.swf' RCE Vulnerability (APSA09-03) - Linux");

  script_tag(name:"summary", value:"Multiple Adobe products are prone to a remote code execution
  (RCE) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- An unspecified error exists in Adobe Flash Player which can be
  exploited via a specially crafted flash application in a '.pdf' file.

  - Error occurs in 'authplay.dll' in Adobe Reader/Acrobat while processing '.swf' content and can
  be exploited to execute arbitrary code.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause code
  execution on the affected application.");

  script_tag(name:"affected", value:"- Adobe Reader/Acrobat version 9.x through 9.1.2

  - Adobe Flash Player version 9.x through 9.0.159.0 and 10.x through 10.0.22.87");

  script_tag(name:"solution", value:"- Update to Adobe Reader/Acrobat version 9.1.3 or later

  - Update to Adobe Flash Player version 9.0.246.0, 10.0.32.18 or later");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/35948/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35759");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35949/");
  script_xref(name:"URL", value:"http://www.kb.cert.org/vuls/id/259425");
  script_xref(name:"URL", value:"https://www.adobe.com/support/security/advisories/apsa09-03.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl", "gb_adobe_prdts_detect_lin.nasl");
  script_mandatory_keys("Adobe/Air_or_Flash_or_Reader/Linux/Installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe_list = make_list("cpe:/a:adobe:flash_player",
                     "cpe:/a:adobe:acrobat_reader");

if(!infos = get_app_version_and_location_from_list(cpe_list:cpe_list, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];
cpe  = infos["cpe"];

if(cpe == "cpe:/a:adobe:flash_player") {
  if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.0.159.0") ||
     version_in_range(version:vers, test_version:"10.0", test_version2:"10.0.22.87")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.0.246.0 or 10.0.32.18", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
} else if(cpe == "cpe:/a:adobe:acrobat_reader") {
  if(version_in_range(version:vers, test_version:"9.0", test_version2:"9.1.2")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"9.1.3", install_path:path);
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);
