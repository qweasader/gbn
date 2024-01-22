# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:ibm:websphere_mq';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106620");
  script_version("2023-11-03T05:05:46+0000");
  script_tag(name:"last_modification", value:"2023-11-03 05:05:46 +0000 (Fri, 03 Nov 2023)");
  script_tag(name:"creation_date", value:"2017-02-27 13:28:29 +0700 (Mon, 27 Feb 2017)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)");

  script_cve_id("CVE-2016-3013", "CVE-2016-3052", "CVE-2016-8915", "CVE-2016-9009");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("IBM WebSphere MQ Multiple Vulnerabilities - February17");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"IBM WebSphere MQ is prone to multiple vulnerabilities:

  - MQ Channel data conversion denial of service (CVE-2016-3013)

  - Java clients might send a password in clear text (CVE-2016-3052)

  - Invalid channel protocol flows cause denial of service on HP-UX (CVE-2016-8915)

  - Cluster channel definition causes denial of service to cluster (CVE-2016-9009)");

  script_tag(name:"affected", value:"IBM WebSphere MQ 8");

  script_tag(name:"solution", value:"Upgrade to version 8.0.0.6.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998661');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998660');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998649');
  script_xref(name:"URL", value:'https://www-01.ibm.com/support/docview.wss?uid=swg21998647');

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_in_range(version: version, test_version: "8.0.0.0", test_version2: "8.0.0.6")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "8.0.0.6", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
