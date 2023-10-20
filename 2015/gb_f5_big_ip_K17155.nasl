# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105357");
  script_cve_id("CVE-2015-4638");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - TMM vulnerability CVE-2015-4638");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17155");

  script_tag(name:"impact", value:"TMM may restart and temporarily fail to process traffic.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The Traffic Management Microkernel (TMM) may restart and produce a core file when a FastL4 virtual server processes a fragmented packet. (CVE-2015-4638 pending)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-09-18 14:24:41 +0200 (Fri, 18 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("F5 Local Security Checks");
  script_copyright("Copyright (C) 2015 Greenbone AG");
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

check_f5["LTM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.1.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.4.0-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;");

check_f5["AFM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.3.0-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;");

check_f5["AVR"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;");

check_f5["APM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.6.0-11.6.0_HF4;11.2.1-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.1.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.6.0-11.6.0_HF4;11.3.0-11.5.2;",
                             "unaffected", "12.0.0;11.6.0_HF5;11.5.3;11.4.1_HF9;");

check_f5["PSM"] = make_array("affected",   "11.2.1-11.4.1;",
                             "unaffected", "11.4.1_HF9;11.2.1_HF16;11.0.0-11.2.0;10.0.0-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.2.1-11.3.0;",
                             "unaffected", "11.2.1_HF16;11.0.0-11.2.0;10.0.0-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.2.1-11.3.0;",
                             "unaffected", "11.2.1_HF16;11.0.0-11.2.0;10.0.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
