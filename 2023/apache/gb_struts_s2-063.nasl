# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:apache:struts";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.104800");
  script_version("2023-10-12T05:05:32+0000");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 10:18:03 +0000 (Wed, 14 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-21 21:06:00 +0000 (Wed, 21 Jun 2023)");

  script_cve_id("CVE-2023-34149");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Struts Security Update (S2-063)");

  script_category(ACT_GATHER_INFO);

  script_family("Web application abuses");
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_dependencies("gb_apache_struts_consolidation.nasl");
  script_mandatory_keys("apache/struts/detected");

  script_tag(name:"summary", value:"Apache Struts is prone to a denial of service (DoS)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"WW-4620 added autoGrowCollectionLimit to
  XWorkListPropertyAccessor, but it only handles setProperty() and not getProperty(). This could
  lead to OOM if developer has set CreateIfNull to true for the underlying Collection type field.");

  script_tag(name:"affected", value:"Apache Struts version 2.0.0 through 6.1.2.");

  script_tag(name:"solution", value:"- Update to version 2.5.31, 6.1.2.1 or later

  - Workaround: Set CreateIfNull to false for Collection type fields (it's by default false if it's
  not set)

  Note: Please set an override for this result if only the workaround has been applied");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-063");
  script_xref(name:"Advisory-ID", value:"S2-063");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/WW-4620");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (isnull(port = get_app_port(cpe: CPE)))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range_exclusive(version: version, test_version_lo: "2.0.0", test_version_up: "2.5.31")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "2.5.31", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

# nb: There was no version like e.g. 3.0, 4.0 and so on
if (version_in_range_exclusive(version: version, test_version_lo: "6.0.0", test_version_up: "6.1.2.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.2.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
