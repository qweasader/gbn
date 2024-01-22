# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805323");
  script_version("2023-10-27T16:11:32+0000");
  script_cve_id("CVE-2015-0564", "CVE-2015-0563", "CVE-2015-0562", "CVE-2015-0561",
                "CVE-2015-0560", "CVE-2015-0559");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:32 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"creation_date", value:"2015-01-14 08:43:33 +0530 (Wed, 14 Jan 2015)");
  script_name("Wireshark Multiple Denial-of-Service Vulnerabilities -01 Jan15 (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service (DoS) vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error within the SMTP dissector.

  - An error within the DEC DNA Routing Protocol dissector.

  - An error within the LPP dissector.

  - Two errors within the WCCP dissector.

  - An error when decypting TLS/SSL sessions.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct multiple denial-of-service attacks.");

  script_tag(name:"affected", value:"Wireshark 1.10.x before 1.10.12 and
  1.12.x before 1.12.3 on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.10.12,
  1.12.3 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/62020");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71922");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71916");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71921");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71917");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71919");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/71918");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-01.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-02.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-03.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-04.html");
  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-04.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirVer = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirVer, test_version:"1.10.0", test_version2:"1.10.11") ||
   version_in_range(version:wirVer, test_version:"1.12.0", test_version2:"1.12.2"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}
