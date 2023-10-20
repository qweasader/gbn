# SPDX-FileCopyrightText: 2011 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = "cpe:/a:awstats:awstats";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103041");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"creation_date", value:"2011-01-25 13:20:03 +0100 (Tue, 25 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_cve_id("CVE-2010-4369");

  script_name("AWStats Unspecified 'LoadPlugin' Directory Traversal Vulnerability");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2011 Greenbone AG");
  script_dependencies("awstats_detect.nasl");
  script_mandatory_keys("awstats/installed");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"AWStats is prone to an unspecified directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input data.");

  script_tag(name:"affected", value:"Versions prior to AWStats 7.0 are vulnerable.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45210");
  script_xref(name:"URL", value:"http://awstats.sourceforge.net/docs/awstats_changelog.txt");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&aid=2537928&group_id=13764&atid=113764");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!vers = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: vers, test_version: "7.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "7.0");
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
