# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:trend_micro:deep_discovery_inspector";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.807355");
  script_version("2023-07-20T05:05:17+0000");
  script_cve_id("CVE-2015-2873", "CVE-2015-2872");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-08-19 17:14:20 +0530 (Fri, 19 Aug 2016)");

  script_name("Trend Micro Deep Discovery Inspector Authentication Bypass and XSS Vulnerabilities");

  script_tag(name:"summary", value:"Trend Micro Deep Discovery Inspector is prone to authentication bypass and cross-site scripting vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to an:

  - Insufficient access restrictions for some sensitive files via a direct
    request to the system log URL, whitelist URL and blacklist URL.

  - Insufficient validation of crafted input passed to index.php and
    to the widget feature.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to gain access to potentially sensitive information and execute
  arbitrary javascript code in the context of current user.");

  script_tag(name:"affected", value:"Trend Micro Deep Discovery Inspector with
  software before 3.5, 3.6, 3.7 and 3.8");

  script_tag(name:"solution", value:"Install the vendor patch.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://esupport.trendmicro.com/solution/en-US/1112206.aspx");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76396");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/76397");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_trendmicro_deep_discovery_inspector_detect.nasl");
  script_mandatory_keys("deep_discovery_inspector/detected");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!trendPort = get_app_port(cpe:CPE))
  exit(0);


if (!trendVersion = get_app_version(cpe:CPE, port:trendPort))
  exit(0);

if (version_is_equal(version:trendVersion, test_version: "3.8")) {
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.8 CP B1263 or 3.8 CP B2047");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.7")) {
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.7 CP B1248 or 3.7 CP B1228 or 3.7 CP B1227");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.6")) {
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.6 CP B1217");
  security_message(port: trendPort, data: report);
  exit(0);
}

if (version_is_equal(version:trendVersion, test_version: "3.5")) {
  report = report_fixed_ver(installed_version: trendVersion, fixed_version: "3.5 CP B1477 or 3.5 CP B1544 or 3.5 CP B1433");
  security_message(port: trendPort, data: report);
  exit(0);
}

exit(0);
