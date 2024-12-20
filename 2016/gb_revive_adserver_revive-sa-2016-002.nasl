# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

CPE = 'cpe:/a:revive:adserver';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106320");
  script_version("2023-07-20T05:05:17+0000");
  script_tag(name:"last_modification", value:"2023-07-20 05:05:17 +0000 (Thu, 20 Jul 2023)");
  script_tag(name:"creation_date", value:"2016-10-04 11:58:57 +0700 (Tue, 04 Oct 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Revive Adserver Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Web application abuses");
  script_dependencies("gb_revive_adserver_detect.nasl");
  script_mandatory_keys("ReviveAdserver/Installed");

  script_tag(name:"summary", value:"Revive Adserver is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"Revive Adserver is prone to multiple vulnerabilities:

  - www/delivery/asyncspc.php is vulnerable to the fairly new Reflected File Download (RFD) web attack vector that
enables attackers to gain complete control over a victim's machine by virtually downloading a file from a
trusted domain.

  - Usernames aren't properly sanitised when creating users on a Revive Adserver instance. Especially, control
characters are not filtered, allowing apparently identical usernames to co-exist in the system, due to the fact
that such characters are normally ignored when an HTML page is displayed in a browser. The issue can beexploited
for user spoofing, although elevated privileges are required to create users within Revive Adserver.

  - Revive Adserver web installer scripts are vulnerable to a reflected XSS attack via the dbHost, dbUser and
possibly other parameters.");

  script_tag(name:"impact", value:"A remote attacker may gain complete control.");

  script_tag(name:"affected", value:"Revive Adserver version 3.2.4 and prior.");

  script_tag(name:"solution", value:"Upgrade to version 3.2.5 or later");

  script_xref(name:"URL", value:"https://www.revive-adserver.com/security/revive-sa-2016-002/");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.2.5")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.5");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);
