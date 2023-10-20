# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:adobe:flash_player";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805803");
  script_version("2023-07-25T05:05:58+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2015-3113");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-06-24 12:14:19 +0530 (Wed, 24 Jun 2015)");
  script_name("Adobe Flash Player Improper FLV Parsing Vulnerability June15 (Mac OS X)");

  script_tag(name:"summary", value:"Adobe Flash Player is prone to an unspecified vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Flaw is due to improper parsing of
  Flash Video (FLV) files by Adobe Flash Player.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to downloaded a malicious flash file and create a back door results
  in taking complete control over the victim's system.");

  script_tag(name:"affected", value:"Adobe Flash Player versions before
  13.0.0.296 and 14.x through 18.x before 18.0.0.194 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version
  13.0.0.296 or 18.0.0.194 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://krebsonsecurity.com/tag/cve-2015-3113");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/flash-player/apsb15-14.html");
  script_xref(name:"URL", value:"http://securityaffairs.co/wordpress/38044/cyber-crime/adobe-fixed-cve-2015-3113.html");
  script_xref(name:"URL", value:"https://www.fireeye.com/blog/threat-research/2015/06/operation-clandestine-wolf-adobe-flash-zero-day.html");
  script_xref(name:"URL", value:"http://blog.trendmicro.com/trendlabs-security-intelligence/adobe-issues-emergency-patch-for-flash-zero-day");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_adobe_prdts_detect_macosx.nasl");
  script_mandatory_keys("Adobe/Flash/Player/MacOSX/Version");

  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!playerVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_is_less(version:playerVer, test_version:"13.0.0.296"))
{
  fix = "13.0.0.296";
  VULN = TRUE;
}

if(version_in_range(version:playerVer, test_version:"14.0", test_version2:"18.0.0.193"))
{
  fix = "18.0.0.194";
  VULN = TRUE;
}

if(VULN)
{
  report = 'Installed version: ' + playerVer + '\n' +
           'Fixed version:     ' + fix + '\n';
  security_message(data:report);
  exit(0);
}
