# SPDX-FileCopyrightText: 2014 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:owncloud:owncloud";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.804660");
  script_version("2023-12-01T16:11:30+0000");
  script_cve_id("CVE-2013-1941", "CVE-2013-1942");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 16:11:30 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2014-07-03 14:22:50 +0530 (Thu, 03 Jul 2014)");
  script_name("ownCloud Multiple Vulnerabilities (oC-SA-2013-014, oC-SA-2013-015)");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"- CVE-2013-1941: Due to using 'time()' as random source in the
  ownCloud installation routine, the entropy of the generated PostgreSQL database user password is
  very low and can be easily guessed. This issue is inside the ownCloud setup routine and is not
  related to any PostgreSQL vulnerability.

  - CVE-2013-1942: A cross-site scripting (XSS) vulnerability allows remote attackers to execute
  arbitrary javascript when a user opens a special crafted URL. This vulnerability exists in the
  bundled 3rdparty plugin 'jPlayer', 'jPlayer' released version 2.2.20 which addresses the problem.");

  script_tag(name:"affected", value:"ownCloud 4.0.x through 4.0.13, 4.5.x through 4.5.8 and 5.0.x
  through 5.0.3.");

  script_tag(name:"solution", value:"Update to version 4.0.14, 4.5.9, 5.0.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://secunia.com/advisories/52986");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/59029");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2013-014.json");
  script_xref(name:"URL", value:"https://github.com/owncloud/security-advisories/blob/master/server/oc-sa-2013-015.json");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_copyright("Copyright (C) 2014 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_http_detect.nasl");
  script_mandatory_keys("owncloud/detected");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_in_range(version:vers, test_version:"4.0.0", test_version2:"4.0.13") ||
   version_in_range(version:vers, test_version:"4.5.0", test_version2:"4.5.8") ||
   version_in_range(version:vers, test_version:"5.0.0", test_version2:"5.0.3")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"4.0.14/4.5.9/5.0.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
