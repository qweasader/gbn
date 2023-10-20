# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140118");
  script_cve_id("CVE-2016-7469");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - XSS vulnerability in the BIG-IP and Enterprise Manager Configuration utilities CVE-2016-7469");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K97285349");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"A stored cross-site scripting (XSS) vulnerability in the BIG-IP Configuration utility device name change page allows an authenticated user to inject arbitrary web script or HTML. Exploitation requires Resource Administrator or Administrator privileges, and it could cause the Configuration utility client to become unstable.");

  script_tag(name:"impact", value:"This vulnerability allows an authenticated attacker to execute a cross-site scripting (XSS) attack. By sending specially crafted input, the attacker can also cause the Configuration utility to become unstable.");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-06 15:11:00 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2017-01-10 09:33:08 +0100 (Tue, 10 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2017 Greenbone AG");
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

check_f5["LTM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;11.2.1;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;10.2.1-10.2.4;");

check_f5["AAM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;");

check_f5["AFM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;");

check_f5["AVR"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;11.2.1;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;");

check_f5["APM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;11.2.1;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;10.2.1-10.2.4;");

check_f5["ASM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;11.2.1;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;10.2.1-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.4.0-11.6.2;11.2.1;",
                             "unaffected", "11.6.3;10.2.1-10.2.4;");

check_f5["LC"]  = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;11.2.1;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;10.2.1-10.2.4;");

check_f5["PEM"] = make_array("affected",   "12.0.0-12.1.2;11.4.0-11.6.2;",
                             "unaffected", "13.0.0-13.1.0;12.1.3;12.1.2_HF1;11.6.3;");

check_f5["PSM"] = make_array("affected",   "11.4.0-11.4.1;",
                             "unaffected", "10.2.1-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.2.1;",
                             "unaffected", "10.2.1-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.2.1;",
                             "unaffected", "10.2.1-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
