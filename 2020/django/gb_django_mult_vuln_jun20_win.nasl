# SPDX-FileCopyrightText: 2020 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.144079");
  script_version("2024-02-15T05:05:40+0000");
  script_tag(name:"last_modification", value:"2024-02-15 05:05:40 +0000 (Thu, 15 Feb 2024)");
  script_tag(name:"creation_date", value:"2020-06-08 05:08:16 +0000 (Mon, 08 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-01-20 15:15:00 +0000 (Wed, 20 Jan 2021)");

  script_cve_id("CVE-2020-13254", "CVE-2020-13596");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django 2.2.x < 2.2.13, 3.0.x < 3.0.7 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Django is prone to multiple vulnerabilities:

  - Potential data leakage via malformed memcached keys (CVE-2020-13254)

  - Possible XSS via admin ForeignKeyRawIdWidget (CVE-2020-13596)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Django versions 2.2.x and 3.0.x.");

  script_tag(name:"solution", value:"Update to version 2.2.13, 3.0.7 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2020/jun/03/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "2.2.0", test_version2: "2.2.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.2.13", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.0.0", test_version2: "3.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
