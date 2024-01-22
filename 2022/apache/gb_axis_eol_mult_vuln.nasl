# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:axis";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.148543");
  script_version("2024-01-09T05:06:46+0000");
  script_tag(name:"last_modification", value:"2024-01-09 05:06:46 +0000 (Tue, 09 Jan 2024)");
  script_tag(name:"creation_date", value:"2022-07-29 04:51:49 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-11 17:16:00 +0000 (Mon, 11 Sep 2023)");

  script_cve_id("CVE-2012-5784", "CVE-2014-3596", "CVE-2018-8032", "CVE-2019-0227",
                "CVE-2023-40743", "CVE-2023-51441");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_name("Apache Axis <= 1.4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("sw_apache_axis_http_detect.nasl");
  script_mandatory_keys("apache/axis/detected");

  script_tag(name:"summary", value:"Apache Axis is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2012-5784: SSL certificate validation security bypass

  - CVE-2014-3596: Insecure certificate validation

  - CVE-2018-8032: Cross-site scripting (XSS) in the default servlet/services

  - CVE-2019-0227: Server-side request forgery (SSRF)

  - CVE-2023-40743: Remote code execution (RCE)

  - CVE-2023-51441: SSRF");

  script_tag(name:"affected", value:"Apache Axis version 1.4 and prior.

  Note: The vulnerability announcement for CVE-2023-40743 from September 2023 and for CVE-2023-51441
  from January 2024 mentions 'Apache Axis through 1.3' as being affected. But as the vendor states
  that no fix is available it is assumed that the latest available version 1.4 (released on
  April 22, 2006) is affected as well.");

  script_tag(name:"solution", value:"No solution was made available by the vendor. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one.

  Notes:

  - Axis 1 has been EOL and the vendor recommend to migrate to a different SOAP engine, such as
  Apache Axis2/Java

  - Version 1.4 was released on April 22, 2006 and some of the flaws have been fixed only in the SVN
  repository which could be used to mitigate these flaws

  - The Apache Axis project does not expect to create an Axis 1.x release fixing these flaws

  - If the remote installation has been build from the SVN sources or is covered via 'backports' of
  a Linux distribution please create an override for this result");

  script_xref(name:"URL", value:"https://lists.apache.org/thread/8nrm5thop8f82pglx4o0jg8wmvy6d9yd");
  script_xref(name:"URL", value:"https://lists.apache.org/thread/gs0qgk2mgss7zfhzdd6ftfjvm4kp7v82");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS-2905");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS-2924");
  script_xref(name:"URL", value:"https://rhinosecuritylabs.com/application-security/cve-2019-0227-expired-domain-rce-apache-axis/");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/09/05/1");
  script_xref(name:"URL", value:"https://web.archive.org/web/20210120072502/https://www.securityfocus.com/bid/56408");

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

if (version_is_less_equal(version: version, test_version: "1.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
