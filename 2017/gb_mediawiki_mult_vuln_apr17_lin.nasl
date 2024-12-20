# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:mediawiki:mediawiki";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106883");
  script_version("2024-07-16T05:05:43+0000");
  script_tag(name:"last_modification", value:"2024-07-16 05:05:43 +0000 (Tue, 16 Jul 2024)");
  script_tag(name:"creation_date", value:"2017-06-20 10:54:15 +0700 (Tue, 20 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-05-17 15:25:00 +0000 (Thu, 17 May 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_cve_id("CVE-2017-0361", "CVE-2017-0362", "CVE-2017-0363", "CVE-2017-0364",
                "CVE-2017-0365", "CVE-2017-0366", "CVE-2017-0367", "CVE-2017-0368",
                "CVE-2017-0369", "CVE-2017-0370", "CVE-2017-0372");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("MediaWiki Multiple Vulnerabilities (Apr 2017) - Linux");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_mediawiki_http_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("mediawiki/detected", "Host/runs_unixoide");

  script_tag(name:"summary", value:"MediaWiki is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following flaws exist:

  - API parameters may now be marked as 'sensitive' to keep their values out of the logs (CVE-2017-0361)

  - 'Mark all pages visited' on the watchlist now requires a CSRF token (CVE-2017-0362)

  - Special:UserLogin and Special:Search allow redirect to interwiki links. (CVE-2017-0363, CVE-2017-0364)

  - XSS in SearchHighlighter::highlightText() when $wgAdvancedSearchHighlighting is true (CVE-2017-0365)

  - SVG filter evasion using default attribute values in DTD declaration (CVE-2017-0366)

  - LocalisationCache will no longer use the temporary directory in its fallback chain when trying to work out
where to write the cache (CVE-2017-0367)

  - Escape content model/format url parameter in message (CVE-2017-0368)

  - Sysops can undelete pages, although the page is protected against it (CVE-2017-0369)

  - Spam blacklist ineffective on encoded URLs inside file inclusion syntax's link parameter (CVE-2017-0370)

  - Parameters injection in SyntaxHighlight results in multiple vulnerabilities (CVE-2017-0372)");

  script_tag(name:"solution", value:"Update to version 1.23.16, 1.27.3, 1.28.2 or later.");

  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-April/000207.html");
  script_xref(name:"URL", value:"https://lists.wikimedia.org/pipermail/mediawiki-announce/2017-April/000209.html");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "1.23.16")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.23.16");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.26.0", test_version2: "1.27.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.27.3");
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "1.28.0", test_version2: "1.28.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.28.2");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
