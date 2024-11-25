# SPDX-FileCopyrightText: 2017 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:hadoop";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106870");
  script_version("2024-11-22T15:40:47+0000");
  script_tag(name:"last_modification", value:"2024-11-22 15:40:47 +0000 (Fri, 22 Nov 2024)");
  script_tag(name:"creation_date", value:"2017-06-14 10:24:52 +0700 (Wed, 14 Jun 2017)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Hadoop Privilege Escalation Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone AG");
  script_family("Privilege escalation");
  script_dependencies("gb_apache_hadoop_detect.nasl");
  script_mandatory_keys("Apache/Hadoop/Installed");

  script_tag(name:"summary", value:"Apache Hadoop is prone to a privilege escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The LinuxContainerExecutor runs docker commands as root with insufficient
input validation. When the docker feature is enabled, authenticated users can run commands as root.");

  script_tag(name:"affected", value:"Apache Hadoop version 2.8.0, 3.0.0-alpha1, 3.0.0-alpha2");

  script_tag(name:"solution", value:"Users of Apache Hadoop 2.8.0 should leave Docker functionality disabled
until Hadoop 2.8.1 is released. Users of Apache Hadoop 3.0.0-alpha1 and Hadoop 3.0.0-alpha2 should upgrade to
Hadoop 3.0.0-alpha3 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2017/q2/394");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version == "2.8.0") {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.8.1 (See reverenced advisory)");
  security_message(port: port, data: report);
  exit(0);
}

if (version == "3.0.0-alpha1" || version == "3.0.0-alpha2") {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.0.0-alpha3");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
