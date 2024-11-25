# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902679");
  script_version("2024-02-15T05:05:40+0000");
  script_cve_id("CVE-2011-2478");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2012-05-21 14:56:42 +0530 (Mon, 21 May 2012)");
  script_name("Google SketchUp '.SKP' File Remote Code Execution Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_google_sketchup_detect_win.nasl");
  script_mandatory_keys("Google/SketchUp/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow attackers to cause SketchUp to exit
  unexpectedly and execute arbitrary code by tricking a user into opening a
  specially crafted '.SKP' file.");
  script_tag(name:"affected", value:"Google SketchUp version 7.1 Maintenance Release 2 and prior on Windows");
  script_tag(name:"insight", value:"The flaw is due to an error when handling certain types of invalid
  edge geometry in a specially crafted SketchUp (.SKP) file.");
  script_tag(name:"solution", value:"Upgrade to Google SketchUp version 8.0 or later.");
  script_tag(name:"summary", value:"Google SketchUp is prone to a remote code execution vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38187");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48363");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/68147");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/VulnerabilityResearchAdvisories/2011/msvr11-006");

  exit(0);
}

include("version_func.inc");

gsVer = get_kb_item("Google/SketchUp/Win/Ver");
if(!gsVer){
  exit(0);
}

if(version_is_less_equal(version:gsVer, test_version:"7.1.6860.0")){
  report = report_fixed_ver(installed_version:gsVer, vulnerable_range:"Less than or equal to 7.1.6860.0");
  security_message(port:0, data:report);
}
