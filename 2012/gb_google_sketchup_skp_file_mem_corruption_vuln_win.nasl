# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803038");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-4894");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-10-09 17:33:06 +0530 (Tue, 09 Oct 2012)");
  script_name("Google SketchUp '.SKP' File Memory Corruption Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50663");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/55598");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2012/msvr12-015");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_sketchup_detect_win.nasl");
  script_mandatory_keys("Google/SketchUp/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow the attacker to execute arbitrary code in
  the context of the user running the application which can compromise the
  application and possibly the system.");
  script_tag(name:"affected", value:"Google SketchUp version 8 Maintenance Release 2 and prior on Windows");
  script_tag(name:"insight", value:"SketchUp fails to parse specially crafted SketchUp document (SKP) files and
  can be exploited to execute arbitrary code or cause a denial of service
  (memory corruption) via a crafted SKP file.");
  script_tag(name:"solution", value:"Upgrade to Google SketchUp version 8 Maintenance Release 3 or later.");
  script_tag(name:"summary", value:"Google SketchUp is prone to a memory corruption vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

gsVer = get_kb_item("Google/SketchUp/Win/Ver");
if(!gsVer){
  exit(0);
}

if(version_is_less_equal(version:gsVer, test_version:"8.0.11752.0")){
  report = report_fixed_ver(installed_version:gsVer, vulnerable_range:"Less than or equal to 8.0.11752.0");
  security_message(port:0, data:report);
}
