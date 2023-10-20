# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105869");
  script_cve_id("CVE-2015-8022");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - BIG-IP file validation vulnerability CVE-2015-8022");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K12401251");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The BIG-IP Configuration utility may not properly validate file type or contents where uploaded files are allowed in the Access Policy Manager customization configuration section.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-06-06 15:11:00 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2016-08-12 13:38:46 +0200 (Fri, 12 Aug 2016)");
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

check_f5["LTM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["AAM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.4.0-11.4.1_HF9;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;");

check_f5["AFM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;");

check_f5["AVR"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;");

check_f5["APM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["ASM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["GTM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["LC"]  = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["PEM"] = make_array("affected",   "11.6.0;11.5.0-11.5.3;11.3.0-11.4.1_HF9;",
                             "unaffected", "12.0.0-12.1.0;11.6.1;11.5.4;11.4.1_HF10;");

check_f5["PSM"] = make_array("affected",   "11.3.0-11.4.1_HF9;11.0.0-11.2.1_HF15;",
                             "unaffected", "11.4.1_HF10;11.2.1_HF16;10.1.0-10.2.4;");

check_f5["WAM"] = make_array("affected",   "11.3.0;11.0.0-11.2.1_HF15;",
                             "unaffected", "11.2.1_HF16;10.1.0-10.2.4;");

check_f5["WOM"] = make_array("affected",   "11.3.0;11.0.0-11.2.1_HF15;",
                             "unaffected", "11.2.1_HF16;10.1.0-10.2.4;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
