# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803214");
  script_version("2023-07-27T05:05:08+0000");
  script_cve_id("CVE-2012-2174");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-07-27 05:05:08 +0000 (Thu, 27 Jul 2023)");
  script_tag(name:"creation_date", value:"2013-01-23 11:08:14 +0530 (Wed, 23 Jan 2013)");
  script_name("IBM Lotus Notes URL Command Injection RCE Vulnerability (Windows)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/49601");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54070");
  script_xref(name:"URL", value:"http://securitytracker.com/id?1027427");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/75320");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/23650");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-12-154");
  script_xref(name:"URL", value:"http://www-304.ibm.com/support/docview.wss?uid=swg21598348");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/119058/IBM-Lotus-Notes-Client-URL-Handler-Command-Injection.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("General");
  script_dependencies("secpod_ibm_lotus_notes_detect_win.nasl");
  script_mandatory_keys("IBM/LotusNotes/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to execute arbitrary code via a
  malicious URLs.");
  script_tag(name:"affected", value:"IBM Lotus Notes Version 8.x before 8.5.3 FP2 on windows");
  script_tag(name:"insight", value:"An error exists within the URL handler which allows attackers to execute
  commands on the target.");
  script_tag(name:"solution", value:"Upgrade to IBM Lotus Notes 8.5.3 FP2 or later.");
  script_tag(name:"summary", value:"IBM Lotus Notes is prone to a remote code execution (RCE) vulnerability.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

lotusVer = get_kb_item("IBM/LotusNotes/Win/Ver");
if(!lotusVer){
  exit(0);
}

if(lotusVer =~ "^8" &&
   version_is_less(version:lotusVer, test_version:"8.5.32.12184")){
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}
