# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/h:f5:big-ip";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105498");
  script_cve_id("CVE-2010-2791", "CVE-2010-2068");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("2023-08-09T05:05:14+0000");

  script_name("F5 BIG-IP - Apache HTTPD vulnerability CVE-2010-2791 and CVE-2010-2068");

  script_xref(name:"URL", value:"https://my.f5.com/manage/s/article/K23332326");

  script_tag(name:"impact", value:"This vulnerability can allow the unauthorized disclosure of information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"mod_proxy in httpd in Apache HTTP Server 2.2.9, when running on Unix, does not close the backend connection if a timeout occurs when reading a response from a persistent connection, which allows remote attackers to obtain a potentially sensitive response intended for a different client in opportunistic circumstances via a normal HTTP request. NOTE: this is the same issue as CVE-2010-2068, but for a different OS and set of affected versions.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");

  script_tag(name:"summary", value:"The remote host is missing a security patch.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"2023-08-09 05:05:14 +0000 (Wed, 09 Aug 2023)");
  script_tag(name:"creation_date", value:"2016-01-05 14:51:42 +0100 (Tue, 05 Jan 2016)");
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

check_f5["LTM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;");

check_f5["APM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;");

check_f5["ASM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;");

check_f5["GTM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "11.0.0-11.6.0;");

check_f5["LC"]  = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "12.0.0;11.0.0-11.6.0;");

check_f5["PSM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "11.0.0-11.4.1;");

check_f5["WAM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "11.0.0-11.3.0;");

check_f5["WOM"] = make_array("affected",   "10.1.0-10.2.4;",
                             "unaffected", "11.0.0-11.3.0;");

if (report = f5_is_vulnerable(ca: check_f5, version: version)) {
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);