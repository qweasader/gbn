# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126273");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2022-12-23 13:58:43 +0000 (Fri, 23 Dec 2022)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-13 06:34:00 +0000 (Fri, 13 Jan 2023)");

  script_cve_id("CVE-2022-47927", "CVE-2023-22909", "CVE-2023-22910", "CVE-2023-22911",
                "CVE-2023-22912");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki < 1.35.9, 1.38.0 < 1.38.5, 1.39.0 < 1.39.1 Multiple Vulnerabilities - Windows");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_windows");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-47927: SQLite creates database files world-readable.

  - CVE-2023-22909: E-Widgets does widget replacement in HTML attributes, which can lead to XSS.

  - CVE-2023-22910: XSS in Wikibase date formatting

  - CVE-2023-22911: SpecialMobileHistory allows remote attackers to cause a denial of service.

  - CVE-2023-22912: CheckUser TokenManager insecurely uses AES-CTR encryption with repeated nonce,
  allowing an adversary to decrypt.");

  script_tag(name:"affected", value:"MediaWiki version prior to 1.35.9, 1.38.0 prior to 1.38.5
  and 1.39.0 prior to 1.39.1.");

  script_tag(name:"solution", value:"Update to version 1.35.9, 1.38.5, 1.39.1 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/hyperkitty/list/mediawiki-announce@lists.wikimedia.org/message/UEMW64LVEH3BEXCJV43CVS6XPYURKWU3/");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-4wpp-22r3-jr8g");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-6fwq-c2cr-jg74");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T323592");
  script_xref(name:"URL", value:"https://phabricator.wikimedia.org/T315123");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.35.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.35.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.38.0", test_version_up: "1.38.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.38.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "1.39.0", test_version_up: "1.39.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.39.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
