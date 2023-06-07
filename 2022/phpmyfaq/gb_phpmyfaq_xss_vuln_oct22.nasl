# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127241");
  script_version("2023-06-06T09:09:18+0000");
  script_tag(name:"last_modification", value:"2023-06-06 09:09:18 +0000 (Tue, 06 Jun 2023)");
  script_tag(name:"creation_date", value:"2022-11-03 10:48:56 +0200 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:M/C:C/I:C/A:C");

  script_cve_id("CVE-2022-3608");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyFAQ < 3.2.0 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to a cross-site scripting (XSS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"An attacker is able to take control of the entire database and
  in some cases read arbitrary file or execute shell commands by writing malicious php file.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.2.0.");

  script_tag(name:"solution", value:"Update to version 3.2.0 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/8f0f3635-9d81-4c55-9826-2ba955c3a850/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.0");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);
