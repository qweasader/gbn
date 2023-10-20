# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:horde:horde_groupware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106403");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-22 11:33:23 +0700 (Tue, 22 Nov 2016)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Horde Webmail Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("horde_detect.nasl");
  script_mandatory_keys("horde/installed");

  script_tag(name:"summary", value:"Horde Webmail is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Horde Webmail is prone to multiple vulnerabilities:

  - PHP script execution via CSRF attack.

  - Upload an SVG image file containing malicious Javascript code");

  script_tag(name:"impact", value:"An attacker may execute shell commands in the context of an admin or user.");

  script_tag(name:"affected", value:"Version 5.2.15 and prior.");

  script_tag(name:"solution", value:"Update to version 5.2.16 or later.");

  script_xref(name:"URL", value:"https://blogs.securiteam.com/index.php/archives/2789");
  script_xref(name:"URL", value:"https://lists.horde.org/archives/announce/2016/001197.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.2.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.16");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
