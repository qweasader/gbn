# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.151658");
  script_version("2024-02-16T05:06:55+0000");
  script_tag(name:"last_modification", value:"2024-02-16 05:06:55 +0000 (Fri, 16 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-02-07 03:24:33 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-15 18:46:48 +0000 (Thu, 15 Feb 2024)");

  script_cve_id("CVE-2024-24680");

  script_tag(name:"qod_type", value:"executable_version");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 3.2.24, 4.x < 4.2.10, 5.x < 5.0.2 DoS Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Denial of Service");
  script_dependencies("gb_django_detect_win.nasl");
  script_mandatory_keys("django/windows/detected");

  script_tag(name:"summary", value:"Django is prone to a denial of service (DoS) vulnerability in
  the intcomma template filter.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The intcomma template filter is subject to a potential denial
  of service attack when used with very long strings.");

  script_tag(name:"affected", value:"Django prior to version 3.2.24, version 4.x prior through
  4.2.9 and 5.x through 5.0.1.");

  script_tag(name:"solution", value:"Update to version 3.2.24, 4.2.10, 5.0.2 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2024/feb/06/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.2.24")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.24", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0", test_version_up: "4.2.10")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.2.10", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "5.0", test_version_up: "5.0.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.0.2", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
