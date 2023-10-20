# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802877");
  script_version("2023-07-28T05:05:23+0000");
  script_cve_id("CVE-2011-1956");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-06-13 15:43:58 +0200 (Mon, 13 Jun 2011)");
  script_name("Wireshark 'bytes_repr_len' Denial of Service Vulnerability (Mac OS X)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/44449/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48389");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/67789");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=5837");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a denial of
  service condition.");
  script_tag(name:"affected", value:"Wireshark version 1.4.5");
  script_tag(name:"insight", value:"The flaw is caused by an error in the 'bytes_repr_len' function, which allows
  remote attackers to cause a denial of service via arbitrary TCP traffic.");
  script_tag(name:"solution", value:"Upgrade to the Wireshark version 1.4.7 or later.");
  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}

include("version_func.inc");

sharkVer = get_kb_item("Wireshark/MacOSX/Version");
if(!sharkVer){
  exit(0);
}

if(version_is_equal(version:sharkVer, test_version:"1.4.5")) {
  report = report_fixed_ver(installed_version:sharkVer, vulnerable_range:"Equal to 1.4.5");
  security_message(port: 0, data: report);
}
