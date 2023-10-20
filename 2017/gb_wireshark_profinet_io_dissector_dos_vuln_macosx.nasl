# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811802");
  script_version("2023-07-14T16:09:27+0000");
  script_cve_id("CVE-2017-13766");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-12-11 02:29:00 +0000 (Mon, 11 Dec 2017)");
  script_tag(name:"creation_date", value:"2017-09-05 16:25:09 +0530 (Tue, 05 Sep 2017)");
  script_name("Wireshark 'Profinet I/O' Dissector DoS Vulnerability (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an out-of-bounds
  write error in 'plugins/profinet/packet-dcerpc-pn-io.c' script.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to make Wireshark crash by injecting a malformed packet onto
  the wire or by convincing someone to read a malformed packet trace file.");

  script_tag(name:"affected", value:"Wireshark version 2.4.0, 2.2.0 to 2.2.8
  on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.4.1 or
  2.2.9 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2017-39.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/100542");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(wirversion == "2.4.0"){
  fix = "2.4.1";
}

else if(wirversion =~ "(^2\.2)")
{
  if(version_is_less(version:wirversion, test_version:"2.2.9")){
    fix = "2.2.9";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:fix);
  security_message(data:report);
  exit(0);
}
