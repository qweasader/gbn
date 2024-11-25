# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:php:php";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143278");
  script_version("2024-02-08T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-02-08 05:05:59 +0000 (Thu, 08 Feb 2024)");
  script_tag(name:"creation_date", value:"2019-12-19 08:59:23 +0000 (Thu, 19 Dec 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-01-03 11:15:00 +0000 (Fri, 03 Jan 2020)");

  script_cve_id("CVE-2019-11046", "CVE-2019-11045", "CVE-2019-11050", "CVE-2019-11047", "CVE-2019-11049");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("PHP Multiple Vulnerabilities (Dec 2019) - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_php_ssh_login_detect.nasl", "gb_php_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("php/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"PHP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"PHP is prone to multiple vulnerabilities:

  - Buffer underflow in bc_shift_addsub (CVE-2019-11046)

  - DirectoryIterator class silently truncates after a null byte (CVE-2019-11045)

  - mail() may release string with refcount==1 twice (CVE-2019-11049)

  - Use-after-free in exif parsing under memory sanitizer (CVE-2019-11050)

  - Heap-buffer-overflow READ in exif (CVE-2019-11047)");

  script_tag(name:"affected", value:"PHP versions 7.3.x prior to 7.3.13 and 7.4.x prior to 7.4.1.");

  script_tag(name:"solution", value:"Update to version 7.3.13, 7.4.1 or later.");

  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.3.13");
  script_xref(name:"URL", value:"https://www.php.net/ChangeLog-7.php#7.4.1");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "7.3.0", test_version2: "7.3.12")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.3.13", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_is_equal(version: version, test_version: "7.4.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.4.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
