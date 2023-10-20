# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.806704");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-7830");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-11-19 12:02:31 +0530 (Thu, 19 Nov 2015)");
  script_name("Wireshark Pcapng File Parser Denial-of-Service Vulnerability Nov15 (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an error in
  'pcapng_read_if_descr_block' function in 'wiretap/pcapng.c' script within the
  pcapng parser which uses too many levels of pointer indirection.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to cause a denial of service via a crafted packet.");

  script_tag(name:"affected", value:"Wireshark version 1.12.x before 1.12.8
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 1.12.8 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"https://www.wireshark.org/security/wnpa-sec-2015-30.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/77101");
  script_xref(name:"URL", value:"https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=11455");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"1.12.0", test_version2:"1.12.7"))
{
  report = 'Installed Version: ' + wirversion + '\n' +
           'Fixed Version:     1.12.8 \n';
  security_message(data:report);
  exit(0);
}