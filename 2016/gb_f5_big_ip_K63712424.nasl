# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140013");
  script_cve_id("CVE-2015-8935");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - PHP vulnerability CVE-2015-8935");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K63712424");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a vulnerability in PHP.");

  script_tag(name:"insight", value:"The sapi_header_op function in main/SAPI.c in PHP before 5.4.38,
  5.5.x before 5.5.22, and 5.6.x before 5.6.6 supports deprecated line folding without considering
  browser compatibility, which allows remote attackers to conduct cross-site scripting (XSS) attacks
  against Internet Explorer by leveraging (1) %0A%20 or (2) %0D%0A%20 mishandling in the header
  function.");

  script_tag(name:"impact", value:"This vulnerability may allow remote attackers to conduct
  cross-site scripting (XSS) attacks by leveraging (1) %0A%20 or (2) %0D%0A%20 mishandling in the
  header function.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)");
  script_tag(name:"creation_date", value:"2016-10-24 15:29:55 +0200 (Mon, 24 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_dependencies("gb_f5_big_ip_ssh_login_detect.nasl");
  script_mandatory_keys("f5/big_ip/version", "f5/big_ip/active_modules");
  exit(0);
}

include("f5.inc");
include("host_details.inc");
include("list_array_func.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, service: "ssh-login"))
  exit(0);

check_f5["LTM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["AAM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["AFM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["AVR"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["APM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["ASM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["GTM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;",
                             "unaffected", "11.6.1;11.5.4;");

check_f5["LC"]  = make_array("affected",   "11.6.0;11.4.0-11.5.3;11.2.1;10.2.1-10.2.4;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["PEM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;",
                             "unaffected", "12.0.0-12.1.1;11.6.1;11.5.4;");

check_f5["PSM"] = make_array("affected",   "11.4.0-11.4.1;10.2.1-10.2.4;",
                             "unaffected", "");

check_f5["WAM"] = make_array("affected",   "11.2.1;10.2.1-10.2.4;",
                             "unaffected", "");

check_f5["WOM"] = make_array("affected",   "11.2.1;10.2.1-10.2.4;",
                             "unaffected", "");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
