# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:cloudera:cloudera_manager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106639");
  script_version("2023-07-25T05:05:58+0000");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2017-03-09 15:29:25 +0700 (Thu, 09 Mar 2017)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-03-09 02:59:00 +0000 (Thu, 09 Mar 2017)");

  script_cve_id("CVE-2016-4948", "CVE-2016-4949", "CVE-2016-4950");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cloudera Manager Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_cloudera_manager_detect.nasl");
  script_mandatory_keys("cloudera_manager/installed");

  script_tag(name:"summary", value:"Cloudera Manager is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Cloudera Manager is prone to multiple vulnerabilities:

  - Multiple cross-site scripting (XSS) vulnerabilities (CVE-2016-4948)

  - Obtain sensitive information via a stderr.log or stdout.log (CVE-2016-4949)

  - Enumeration of user sessions via a request to /api/v11/users/sessions (CVE-2016-4950)");

  script_tag(name:"affected", value:"Cloudera 5.5.0 and previous.");

  script_tag(name:"solution", value:"Update to 5.5.1 or newer versions.");

  script_xref(name:"URL", value:"http://2016.hack.lu/archive/2016/Wavestone%20-%20Hack.lu%202016%20-%20Hadoop%20safari%20-%20Hunting%20for%20vulnerabilities%20-%20v1.0.pdf");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "5.5.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.5.1");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
