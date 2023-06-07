# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:discourse:discourse";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117155");
  script_version("2021-08-26T14:01:06+0000");
  script_tag(name:"last_modification", value:"2021-08-26 14:01:06 +0000 (Thu, 26 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-01-15 09:41:33 +0000 (Fri, 15 Jan 2021)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-21 17:15:00 +0000 (Wed, 21 Apr 2021)");

  script_cve_id("CVE-2021-3138");

  script_name("Discourse < 2.7.0.beta4 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_discourse_detect.nasl");
  script_mandatory_keys("discourse/detected");

  script_tag(name:"summary", value:"Discourse is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following flaws exist / The following security
  fixes are included:

  - Attach DiscourseConnect (SSO) nonce to current session.

  - Rate limit MFA by login if possible. A rate-limit bypass leads to a bypass of the 2FA
  requirement for certain forms. (CVE-2021-3138)");

  script_tag(name:"affected", value:"Discourse up to and including version 2.7.0.beta3.");

  script_tag(name:"solution", value:"Update to version 2.7.0.beta4 or later.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://github.com/Mesh3l911/Disource");
  script_xref(name:"URL", value:"https://meta.discourse.org/t/2-7-0-beta4-discourseconnect-topic-timer-ui-revamp-login-modal-ui-revamp-and-more/180213");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) )
  exit( 0 );

vers = infos["version"];

if( version_is_less( version:vers, test_version:"2.7.0" ) ||
    version_in_range( version:vers, test_version:"2.7.0.beta1", test_version2:"2.7.0.beta3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.0.beta4", install_path:infos["location"] );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
