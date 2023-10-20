# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105425");
  script_cve_id("CVE-2015-3238");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - PAM vulnerability CVE-2015-3238");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K17494");

  script_tag(name:"impact", value:"This vulnerability allows the unauthorized disclosure of information and disruption of service.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The _unix_run_helper_binary function in the pam_unix module in Linux-PAM (aka pam) before 1.2.1, when unable to directly access passwords, allows local users to enumerate usernames or cause a denial of service (hang) via a large password. (CVE-2015-3238)");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-01-03 15:01:00 +0000 (Thu, 03 Jan 2019)");
  script_tag(name:"creation_date", value:"2015-10-28 11:01:54 +0100 (Wed, 28 Oct 2015)");
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

check_f5["LTM"] = make_array("affected",   "11.0.0-11.6.0_HF5;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["AAM"] = make_array("affected",   "11.4.0-11.6.0_HF5;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["AFM"] = make_array("affected",   "11.3.0-11.6.0_HF5;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["AVR"] = make_array("affected",   "11.0.0-11.6.0_HF5;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["APM"] = make_array("affected",   "11.0.0-11.6.0_HF5;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["ASM"] = make_array("affected",   "11.0.0-11.6.0_HF5;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["GTM"] = make_array("affected",   "11.0.0-11.6.0_HF5;10.1.0-10.2.4;",
                             "unaffected", "11.6.0_HF6;");

check_f5["LC"]  = make_array("affected",   "11.0.0-11.6.0;10.1.0-10.2.4;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

check_f5["PEM"] = make_array("affected",   "11.3.0-11.6.0_HF5;",
                             "unaffected", "12.1.0;12.0.0;11.6.0_HF6;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
