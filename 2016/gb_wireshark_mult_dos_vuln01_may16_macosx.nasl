# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:wireshark:wireshark";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807578");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2016-4084", "CVE-2016-4083", "CVE-2016-4077", "CVE-2016-4076");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-12-03 03:27:00 +0000 (Sat, 03 Dec 2016)");
  script_tag(name:"creation_date", value:"2016-05-03 11:50:51 +0530 (Tue, 03 May 2016)");
  script_name("Wireshark Multiple Denial of Service Vulnerabilities May16 (Mac OS X)");

  script_tag(name:"summary", value:"Wireshark is prone to multiple denial of service vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - 'epan/dissectors/packet-ncp2222.inc' script in the NCP dissector does not
    properly initialize memory for search patterns.

  - 'epan/reassemble.c' script in TShark relies on incorrect special-case
    handling of truncated Tvb data structures.

  - 'epan/dissectors/packet-mswsp.c' script in the MS-WSP dissector does not
    ensure that data is available before array allocation.

  - An integer signedness error in 'epan/dissectors/packet-mswsp.c' script in
    the MS-WSP dissector");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to conduct denial of service attack.");

  script_tag(name:"affected", value:"Wireshark version 2.0.x before 2.0.3
  on Mac OS X");

  script_tag(name:"solution", value:"Upgrade to Wireshark version 2.0.3 or
  later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"executable_version");

  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-27.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-20.html");
  script_xref(name:"URL", value:"http://www.wireshark.org/security/wnpa-sec-2016-19.html");

  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_wireshark_detect_macosx.nasl");
  script_mandatory_keys("Wireshark/MacOSX/Version");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(!wirversion = get_app_version(cpe:CPE)){
  exit(0);
}

if(version_in_range(version:wirversion, test_version:"2.0.0", test_version2:"2.0.2"))
{
  report = report_fixed_ver(installed_version:wirversion, fixed_version:"2.0.3");
  security_message(data:report);
  exit(0);
}
