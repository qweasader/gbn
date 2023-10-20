# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105229");
  script_cve_id("CVE-2015-1050");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - ASM cross-site scripting (XSS) vulnerability CVE-2015-1050");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K16081");

  script_tag(name:"impact", value:"Remote attackers may be able to inject arbitrary web script or HTML by way of the Response Body field.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cross-site scripting (XSS) vulnerability in F5 BIG-IP Application Security Manager (ASM) before 11.6.0
allows an authenticated user to inject arbitrary web script or HTML via the Response Body field.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"F5 BIG-IP is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2015-03-03 11:43:44 +0100 (Tue, 03 Mar 2015)");
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

check_f5["ASM"] = make_array("affected",   "11.0.0-11.5.2;10.1.0-10.2.4;",
                             "unaffected", "11.6.0;11.5.3;11.5.2_HF1;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);