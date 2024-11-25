# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105555");
  script_cve_id("CVE-2013-4351");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_version("2024-05-29T05:05:18+0000");

  script_name("F5 BIG-IP - GnuPG vulnerability CVE-2013-4351");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K50413110");

  script_tag(name:"impact", value:"A remote attacker may exploit this flaw to bypass the intended cryptographic protection mechanism.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"GnuPG 1.4.x, 2.0.x, and 2.1.x treats a key flags subpacket with all bits cleared (no usage permitted) as if it has all bits set (all usage permitted), which might allow remote attackers to bypass intended cryptographic protection mechanisms by leveraging the subkey.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2024-05-29 05:05:18 +0000 (Wed, 29 May 2024)");
  script_tag(name:"creation_date", value:"2016-02-23 10:33:41 +0100 (Tue, 23 Feb 2016)");
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

check_f5["LTM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["AAM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.4.0-11.4.1;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["AFM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.3.0-11.4.1;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["AVR"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.0.0-11.4.1;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["APM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["ASM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.0.0-11.4.1;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["GTM"] = make_array("affected",   "11.6.1-11.6.3;11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["LC"]  = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["PEM"] = make_array("affected",   "13.0.0-13.1.0;12.0.0-12.1.3;11.6.1-11.6.3;12.0.0;11.3.0-11.4.1;",
                             "unaffected", "11.5.0-11.6.0;");

check_f5["PSM"] = make_array("affected",   "11.0.0-11.4.1;10.1.0-10.2.4;",
                             "unaffected", "");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
