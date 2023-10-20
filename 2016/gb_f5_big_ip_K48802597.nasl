# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105760");
  script_cve_id("CVE-2013-5825", "CVE-2013-5830");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - Java vulnerabilities CVE-2013-5825 and CVE-2013-5830");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K48802597");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect availability via vectors related to JAXP.
Unspecified vulnerability in Oracle Java SE 7u40 and earlier, Java SE 6u60 and earlier, Java SE 5.0u51 and earlier, JRockit R28.2.8 and earlier, JRockit R27.7.6 and earlier, and Java SE Embedded 7u40 and earlier allows remote attackers to affect confidentiality, integrity, and availability via unknown vectors related to Libraries.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-06-13 11:39:31 +0200 (Mon, 13 Jun 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_f5_big_ip_version.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("version_func.inc");
include("host_details.inc");
include("list_array_func.inc");
include("f5.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

check_f5["LTM"] = make_array("affected",   "11.6.0;11.0.0-11.5.4;10.1.0-10.2.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["AAM"] = make_array("affected",   "11.6.0;11.4.0-11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["AFM"] = make_array("affected",   "11.6.0;11.3.0-11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["AVR"] = make_array("affected",   "11.6.0;11.0.0-11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["APM"] = make_array("affected",   "11.6.0;11.0.0-11.5.4;10.1.0-10.2.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["ASM"] = make_array("affected",   "11.6.0;11.0.0-11.5.4;10.1.0-10.2.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["GTM"] = make_array("affected",   "11.6.0;11.0.0-11.5.4;10.1.0-10.2.4;",
                             "unaffected", "11.6.1;11.5.4_HF2;");

check_f5["LC"]  = make_array("affected",   "11.6.0;11.0.0-11.5.4;10.1.0-10.2.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

check_f5["PEM"] = make_array("affected",   "11.6.0;11.3.0-11.5.4;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4_HF2;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
