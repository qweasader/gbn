# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_application_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801646");
  script_version("2024-11-14T05:05:31+0000");
  script_tag(name:"last_modification", value:"2024-11-14 05:05:31 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2010-12-09 06:49:11 +0100 (Thu, 09 Dec 2010)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");

  script_cve_id("CVE-2010-0783", "CVE-2010-0785");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere Application Server XSS and CSRF Vulnerabilities (Nov 2010)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Web Servers");
  script_dependencies("gb_ibm_websphere_consolidation.nasl");
  script_mandatory_keys("ibm/websphere/detected");

  script_tag(name:"summary", value:"IBM WebSphere Application Server is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Cross-site scripting (XSS) in the administrative console due to improper filtering on input
  values

  - Input sanitation error in the administrative console can be exploited to conduct cross-site
  request forgery (CSRF) attacks.");

  script_tag(name:"impact", value:"Successful exploitation will let attackers to conduct cross-site
  scripting and cross-site request forgery attacks.");

  script_tag(name:"affected", value:"IBM WebSphere Application Server versions 6.1.x prior to
  6.1.0.35 and 7.0.x prior to 7.0.0.13.");

  script_tag(name:"solution", value:"Update to version 6.1.0.35, 7.0.0.13 or later.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/42136");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44670");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2010/Nov/1024686.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27004980");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_in_range_exclusive(version: version, test_version_lo: "6.0", test_version_up: "6.1.0.35")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.35");
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "7.0", test_version_up: "7.0.0.13")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "7.0.0.13");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
