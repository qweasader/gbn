# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:opmantek:nmis';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106245");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-09-15 09:47:18 +0700 (Thu, 15 Sep 2016)");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-04-14 15:11:00 +0000 (Fri, 14 Apr 2017)");

  script_cve_id("CVE-2016-5642", "CVE-2016-6534");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Opmantek NMIS Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("General");
  script_dependencies("gb_opmantek_nmis_detect.nasl");
  script_mandatory_keys("opmantek_nmis/installed");

  script_tag(name:"summary", value:"Opmantek NMIS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"NMIS is prone to two vulnerabilities:

A stored server XSS vulnerability exists due to insufficient filtering of SNMP agent supplied data before the
affected software stores and displays the data. The stored XSS payload is delivered to the affected software
during the SNMP data collect operation performed when adding and updating a node (CVE-2016-5642).

A command injection vulnerability in the web application component of NMIS exists due to insufficient input
validation. The command injection vulnerability exists in the tools.pl CGI script via the 'node' parameter when
the 'act' parameter is set to 'tool_system_finger'. The user must be authenticated and granted the tls_finger
permission, which does not appear to be enabled by default (CVE-2016-6534).");

  script_tag(name:"impact", value:"A successful exploit could allow an attacker to execute arbitrary script
code in the context of the interface, or an authenticated attacker may execute arbitrary commands.");

  script_tag(name:"affected", value:"NMIS version 4.x and 8.x.");

  script_tag(name:"solution", value:"Update to 4.3.7c, 8.5.12G or later");

  script_xref(name:"URL", value:"https://community.rapid7.com/community/infosec/blog/2016/09/07/multiple-disclosures-for-multiple-network-management-systems-part-2");

  exit(0);
}

include("host_details.inc");
include("revisions-lib.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version =~ "^8\.") {
  if (revcomp(a: version, b: "8.5.12g") < 0) {
    report = report_fixed_ver(installed_version: toupper(version), fixed_version: "8.5.12G");
    security_message(port: port, data: report);
    exit(0);
  }
}

if (version =~ "^4\.") {
  if (revcomp(a: version, b: "4.3.7c") < 0) {
    report = report_fixed_ver(installed_version: version, fixed_version: "4.3.7c");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
