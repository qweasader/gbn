# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801761");
  script_version("2023-03-24T10:19:42+0000");
  script_tag(name:"last_modification", value:"2023-03-24 10:19:42 +0000 (Fri, 24 Mar 2023)");
  script_tag(name:"creation_date", value:"2011-03-09 16:08:21 +0100 (Wed, 09 Mar 2011)");
  script_cve_id("CVE-2011-1143");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_name("Wireshark DoS Vulnerability March-11 (Windows)");

  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_win.nasl");
  script_mandatory_keys("Wireshark/Win/Ver");
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to cause a denial of
  service.");
  script_tag(name:"affected", value:"Wireshark version prior to 1.4.4");
  script_tag(name:"insight", value:"The flaw is due to an error in 'epan/dissectors/packet-ntlmssp.c' in
  the NTLMSSP dissector");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.4");
  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5157");
  script_xref(name:"URL", value:"http://www.wireshark.org/docs/relnotes/wireshark-1.4.4.html");
  script_xref(name:"URL", value:"http://anonsvn.wireshark.org/viewvc?revision=34018&view=revision");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

wiresharkVer = get_kb_item("Wireshark/Win/Ver");
if(!wiresharkVer){
  exit(0);
}

if(version_is_less(version:wiresharkVer, test_version:"1.4.4")){
  report = report_fixed_ver(installed_version:wiresharkVer, fixed_version:"1.4.4");
  security_message(port: 0, data: report);
}
