# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105347");
  script_cve_id("CVE-2015-3628");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_version("2023-09-13T05:05:22+0000");

  script_name("F5 BIG-IP - iCall privilege escalation vulnerability CVE-2015-3628");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K16728");

  script_tag(name:"impact", value:"An authenticated user with limited access (Resource Administration) may be able to escalate privileges and gain administrative access.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An authenticated user, with Resource Administrator role permissions, is able to use iCall scripts and associated handlers to create and modify user account properties.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a privilege escalation vulnerability");

  script_tag(name:"last_modification", value:"2023-09-13 05:05:22 +0000 (Wed, 13 Sep 2023)");
  script_tag(name:"creation_date", value:"2015-09-07 16:56:39 +0200 (Mon, 07 Sep 2015)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"package");
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

check_f5["LTM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.6.0;11.4.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["AFM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["AVR"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;");

check_f5["APM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.6.0;11.3.0-11.5.3;",
                             "unaffected", "12.0.0;11.6.0_HF6;11.5.4;11.5.3_HF2;11.4.1_HF10;");

check_f5["PSM"] = make_array("affected",   "11.3.0-11.4.1;",
                             "unaffected", "11.4.1_HF10;11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.3.0;",
                             "unaffected", "11.0.0-11.2.1;10.0.0-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.3.0;",
                             "unaffected", "11.0.0-11.2.1;10.0.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
