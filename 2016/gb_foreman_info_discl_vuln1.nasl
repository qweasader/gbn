# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:theforeman:foreman';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106419");
  script_version("2023-07-21T05:05:22+0000");
  script_tag(name:"last_modification", value:"2023-07-21 05:05:22 +0000 (Fri, 21 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-11-29 08:20:28 +0700 (Tue, 29 Nov 2016)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-08 17:02:00 +0000 (Fri, 08 Mar 2019)");

  script_cve_id("CVE-2016-5390");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Foreman Information Disclosure Vulnerability-01");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_foreman_detect.nasl");
  script_mandatory_keys("foreman/installed");

  script_tag(name:"summary", value:"Foreman is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Non-admin users with the view_hosts permission containing a filter are
able to access API routes beneath 'hosts' such as GET /api/v2/hosts/secrethost/interfaces without the filter
being taken into account. This allows users to access network interface details (including BMC login details)
for any host.");

  script_tag(name:"affected", value:"Version 1.10.0 to 1.12.0, except 1.11.4");

  script_tag(name:"solution", value:"Upgrade to 1.11.4, 1.12.1 or later.");

  script_xref(name:"URL", value:"https://theforeman.org/security.html#2016-5390");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_in_range(version: version, test_version: "1.10.0", test_version2: "1.12.0")) {
  if (version != "1.11.4") {
    report = report_fixed_ver(installed_version: version, fixed_version: "1.12.1");
    security_message(port: port, data: report);
    exit(0);
  }
}

exit(0);
