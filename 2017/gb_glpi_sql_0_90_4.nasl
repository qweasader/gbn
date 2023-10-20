# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE ='cpe:/a:glpi-project:glpi';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107227");
  script_version("2023-07-14T16:09:27+0000");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-07-14 16:09:27 +0000 (Fri, 14 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-06-28 14:43:29 +0200 (Wed, 28 Jun 2017)");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_name("GLPI 0.90.4 SQL Injection Vulnerability");

  script_tag(name:"summary", value:"GLPI is prone to SQL Injection");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"affected", value:"GLPI 0.90.4");
  script_tag(name:"insight", value:"The attack is due to the variable dbenc which when configured by the admin to big5, it allows SQL injection in almost all the forms of the application.");
  script_tag(name:"impact", value:"Successful exploitation will allow an authenticated remote attacker to execute arbitrary
  SQL commands by using the [ELIDED] character when the database is configured to use asian encoding (BIG 5).");
  script_tag(name:"solution", value:"Update GLPI to version 9.1 or later.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_family("Web application abuses");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_dependencies("gb_glpi_detect.nasl");
  script_mandatory_keys("glpi/detected");

  script_xref(name:"URL", value:"https://www.exploit-db.com/exploits/42262/?rss");
  script_xref(name:"URL", value:"https://github.com/glpi-project/glpi/releases");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if (version_is_equal(version:vers, test_version:"0.90.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"9.1");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
