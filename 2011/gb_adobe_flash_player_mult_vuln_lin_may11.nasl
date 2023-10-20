# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801791");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-05-23 15:31:07 +0200 (Mon, 23 May 2011)");
  script_cve_id("CVE-2011-0579", "CVE-2011-0618", "CVE-2011-0619", "CVE-2011-0620",
                "CVE-2011-0621", "CVE-2011-0622", "CVE-2011-0623", "CVE-2011-0624",
                "CVE-2011-0625", "CVE-2011-0626", "CVE-2011-0627");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Player Multiple Vulnerabilities May-2011 (Linux)");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb11-12.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47806");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47807");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47808");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47809");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47810");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47811");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47812");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47813");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47814");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47815");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/47847");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("General");
  script_dependencies("gb_adobe_flash_player_detect_lin.nasl");
  script_mandatory_keys("AdobeFlashPlayer/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code or cause
  a denial of service condition.");
  script_tag(name:"affected", value:"Adobe Flash Player version 10.2.159.1 and prior on Linux");
  script_tag(name:"insight", value:"The flaws are caused by memory corruptions, integer overflow errors and bounds
  checking errors when processing malformed Flash content, which could be
  exploited by attackers to execute arbitrary code by tricking a user into
  visiting a specially crafted web page.");
  script_tag(name:"solution", value:"Upgrade to Adobe Flash Player version 10.3.181.14 or later.");
  script_tag(name:"summary", value:"Adobe Flash Player is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

vers = get_kb_item("AdobeFlashPlayer/Linux/Ver");
if(!vers)
  exit(0);

vers = ereg_replace(pattern:",", string:vers, replace: ".");

if(version_is_less_equal(version:vers, test_version:"10.2.159.1")){
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Less than or equal to 10.2.159.1");
  security_message(port: 0, data: report);
}
