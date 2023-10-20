# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800844");
  script_version("2023-07-27T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2009-07-17 12:47:28 +0200 (Fri, 17 Jul 2009)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-2477");
  script_name("Mozilla Firefox JavaScript Compiler Code Execution Vulnerability (Linux)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35798");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/35707");
  script_xref(name:"URL", value:"http://www.milw0rm.com/exploits/9137");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1868");
  script_xref(name:"URL", value:"http://www.mozilla.org/security/announce/2009/mfsa2009-41.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("General");
  script_dependencies("gb_firefox_detect_lin.nasl");
  script_mandatory_keys("Firefox/Linux/Ver");
  script_tag(name:"impact", value:"Successful exploitation will let attackers to execute arbitrary code which
  results in memory corruption.");
  script_tag(name:"affected", value:"Firefox version 3.5 and prior on Linux");
  script_tag(name:"insight", value:"The flaw is due to an error when processing JavaScript code handling
  'font' HTML tags and can be exploited to cause memory corruption.");
  script_tag(name:"solution", value:"Upgrade to Firefox version 3.5.1 or later.");
  script_tag(name:"summary", value:"Mozilla Firefox browser is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

ffVer = get_kb_item("Firefox/Linux/Ver");
if(!ffVer)
  exit(0);

if(version_is_less(version:ffVer, test_version:"3.5.1")){
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"3.5.1");
  security_message(port: 0, data: report);
}
