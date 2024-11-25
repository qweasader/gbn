# SPDX-FileCopyrightText: 2009 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900475");
  script_version("2024-02-15T05:05:39+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:39 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2009-03-03 06:56:37 +0100 (Tue, 03 Mar 2009)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-0388");
  script_name("TightVNC ClientConnection Multiple Integer Overflow Vulnerabilities - Linux");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/7990");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/33568");
  script_xref(name:"URL", value:"http://milw0rm.com/exploits/8024");
  script_xref(name:"URL", value:"http://www.coresecurity.com/content/vnc-integer-overflows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone AG");
  script_family("Buffer overflow");
  script_dependencies("secpod_tightvnc_detect_lin.nasl");
  script_mandatory_keys("TightVNC/Linux/Ver");
  script_tag(name:"affected", value:"TightVNC version 1.3.9 and prior on Linux.");
  script_tag(name:"insight", value:"Multiple Integer Overflow due to signedness errors within the functions
  ClientConnection::CheckBufferSize and ClientConnection::CheckFileZipBufferSize
  in ClientConnection.cpp file fails to validate user input.");
  script_tag(name:"solution", value:"Upgrade to the latest version 1.3.10.");
  script_tag(name:"summary", value:"TightVNC is prone to Multiple Integer Overflow Vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes in the
  context of the application and may cause remote code execution to compromise
  the affected remote system.");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

tvncVer = get_kb_item("TightVNC/Linux/Ver");
if(!tvncVer)
  exit(0);

if(version_is_less_equal(version:tvncVer, test_version:"1.3.9")){
  report = report_fixed_ver(installed_version:tvncVer, vulnerable_range:"Less than or equal to 1.3.9");
  security_message(port: 0, data: report);
}
