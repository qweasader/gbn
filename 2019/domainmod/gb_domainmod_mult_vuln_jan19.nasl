# Copyright (C) 2019 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113327");
  script_version("2021-09-20T13:38:59+0000");
  script_tag(name:"last_modification", value:"2021-09-20 13:38:59 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-01-22 15:55:07 +0200 (Tue, 22 Jan 2019)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-07-19 03:31:00 +0000 (Fri, 19 Jul 2019)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11558", "CVE-2018-11559", "CVE-2018-19136", "CVE-2018-19137", "CVE-2018-19749", "CVE-2018-19750",
                "CVE-2018-19751", "CVE-2018-19752", "CVE-2018-19892", "CVE-2018-19913", "CVE-2018-19914",
                "CVE-2018-19915", "CVE-2018-20009", "CVE-2018-20010", "CVE-2018-20011", "CVE-2019-1010094",
                "CVE-2019-1010095", "CVE-2019-1010096");

  script_name("DomainMOD < 4.12.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_domainmod_http_detect.nasl");
  script_mandatory_keys("domainmod/detected");

  script_tag(name:"summary", value:"DomainMOD is prone to multiple vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS in the '/settings/profile/index.php' new_first_name parameter

  - Stored XSS in the '/settings/profile/index.php' new_last_name parameter

  - XSS via the admin/dw/add-server.php DisplayName, HostName, or UserName field

  - XSS via the assets/add/account-owner.php Owner name field

  - XSS via the admin/domain-fields/ notes field in an Add Custom Field action for Custom Domain Fields

  - XSS via the admin/ssl-fields/add.php notes field for Custom SSL Fields

  - XSS via the assets/add/registrar.php notes field for the Registrar

  - XSS via the assets/edit/registrar-account.php raid parameter

  - XSS via the assets/edit/ip-address.php ipid parameter

  - XSS via the assets/add/ssl-provider.php SSL Provider Name or SSL Provider URL field

  - XSS via the assets/add/ssl-provider-account.php username field

  - XSS via the assets/add/registrar-accounts.php UserName, Reseller ID, or notes field

  - XSS via the assets/add/dns.php Profile Name or notes field

  - XSS via the assets/edit/host.php Web Host Name or Web Host URL field

  - CSRF in /settings/password that allows an attacker to change the admin password

  - CSRF in /admin/users/add.php allows an attacker to add an administrator account

  - CSRF in /admin/users/edit.php?uid=2 allows an attacker to change the read-only user to admin");
  script_tag(name:"impact", value:"Successful exploitation would allow an attacker to craft a malicious
  link containing arbitrary JavaScript or HTML or perform actions in the context of another user.");
  script_tag(name:"affected", value:"DomainMOD prior to version 4.12.0.");
  script_tag(name:"solution", value:"Update to DomainMOD version 4.12.0 or later.");

  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/65");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/66");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/79");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/81");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/82");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/83");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/84");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/86");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/87");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/88");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/79#issuecomment-460035220");

  exit(0);
}

CPE = "cpe:/a:domainmod:domainmod";

include( "host_details.inc" );
include( "version_func.inc" );

if( ! port = get_app_port( cpe: CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe: CPE, port: port ) ) exit( 0 );

if( version_is_less( version: version, test_version: "4.12.0" ) ) {
  report = report_fixed_ver( installed_version: version, fixed_version: "4.12.0" );
  security_message( data: report, port: port );
  exit( 0 );
}

exit( 99 );
