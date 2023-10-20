# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:ibm:websphere_mq";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805547");
  script_version("2023-07-25T05:05:58+0000");
  script_cve_id("CVE-2015-0176");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-07-25 05:05:58 +0000 (Tue, 25 Jul 2023)");
  script_tag(name:"creation_date", value:"2015-05-06 12:12:34 +0530 (Wed, 06 May 2015)");

  script_name("IBM WebSphere MQ XR WebSockets listener Cross-Site Scripting Vulnerability");

  script_tag(name:"summary", value:"IBM WebSphere MQ is prone to a cross-site scripting (XSS) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to improper validation
  of user-supplied input.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote
  attacker to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server.");

  script_tag(name:"affected", value:"IBM WebSphere MQ version 8.x before 8.0.0.2");

  script_tag(name:"solution", value:"Upgrade to IBM WebSphere MQ version 8.0.0.2 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21699549");

  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_ibm_websphere_mq_consolidation.nasl");
  script_mandatory_keys("ibm_websphere_mq/detected");

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

if(version_in_range(version:version, test_version:"8.0", test_version2:"8.0.0.1")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"8.0.0.2", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
