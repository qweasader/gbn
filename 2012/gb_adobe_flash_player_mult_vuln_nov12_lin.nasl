# SPDX-FileCopyrightText: 2012 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803046");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277",
                "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2012-11-08 18:02:59 +0530 (Thu, 08 Nov 2012)");
  script_name("Adobe Flash Player Multiple Vulnerabilities - November12 (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/51213");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56412");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb12-24.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application.");
  script_tag(name:"affected", value:"Adobe Flash Player version before 10.3.183.43, 11.x before 11.2.202.251 on Linux");
  script_tag(name:"insight", value:"Multiple unspecified errors exist due to memory corruption, buffer overflow
  that could lead to code execution.");
  script_tag(name:"solution", value:"Update to Adobe Flash Player version 10.3.183.43 or 11.2.202.251 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(vers && "," >< vers) {
  vers = ereg_replace(pattern:",", string:vers, replace: ".");
}

if(vers) {
  if(version_is_less(version:vers, test_version:"10.3.183.43") ||
     version_in_range(version:vers, test_version:"11.0", test_version2:"11.2.202.250")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}
