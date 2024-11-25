# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.152548");
  script_version("2024-09-12T07:59:53+0000");
  script_tag(name:"last_modification", value:"2024-09-12 07:59:53 +0000 (Thu, 12 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-07-04 02:56:23 +0000 (Thu, 04 Jul 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-09-11 14:03:57 +0000 (Wed, 11 Sep 2024)");

  script_cve_id("CVE-2024-35234", "CVE-2024-35227", "CVE-2024-36113", "CVE-2024-37165",
                "CVE-2024-37299", "CVE-2024-38360", "CVE-2024-39320");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Discourse 3.3.x < 3.3.0.beta3 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("General");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2024-35234: Stored-dom XSS via Facebook Oneboxes

  - CVE-2024-35227: DoS through Onebox

  - CVE-2024-36113: Missing authorization checks for suspending admins/moderators

  - CVE-2024-37165: XSS via Onebox system

  - CVE-2024-37299: DoS via Tag Group

  - CVE-2024-38360: DoS via Watched Words

  - CVE-2024-39320: Iframe injection though default site setting");

  script_tag(name:"affected", value:"Discourse versions 3.3.x through 3.3.0.beta2.");

  script_tag(name:"solution", value:"Update to version 3.3.0.beta3 or later.");

  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-5chg-hm8c-wc58");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-664f-xwjw-752c");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-3w3f-76p7-3c4g");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-cx83-5p6x-9qh9");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-4j6h-9pjp-5476");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-68pm-hm8x-pq2p");
  script_xref(name:"URL", value:"https://github.com/discourse/discourse/security/advisories/GHSA-4p82-xh38-gq4p");

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

if (version_in_range(version: version, test_version: "3.3.0.beta", test_version2: "3.3.0.beta2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.3.0.beta3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
