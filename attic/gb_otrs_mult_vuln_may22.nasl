# Copyright (C) 2022 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126175");
  script_version("2022-10-31T10:12:00+0000");
  script_tag(name:"last_modification", value:"2022-10-31 10:12:00 +0000 (Mon, 31 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 09:25:57 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-28 17:02:00 +0000 (Mon, 28 Mar 2022)");

  script_cve_id("CVE-2022-1004", "CVE-2022-0475");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS Multiple Vulnerabilities (OSA-2022-06, OSA-2022-05)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"OTRS is prone to multiple vulnerabilities.

  This VT has been deprecated as a duplicate of the VT 'OTRS Multiple Vulnerabilities (OSA-2022-03,
  OSA-2022-05, OSA-2022-06)' (OID:1.3.6.1.4.1.25623.1.0.147824).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1004: Accounted time is shown in the Ticket Detail View (External Interface), even if
  ExternalFrontendTicketDetailViewAccountedTimeDisplay is disabled.

  - CVE-2022-0475: Malicious translator is able to inject JavaScript code in few translatable
  strings (where HTML is allowed). The code could be executed in the Package manager.");

  script_tag(name:"affected", value:"OTRS version 7.0.x through 7.0.32 and 8.0.x through 8.0.19.");

  script_tag(name:"solution", value:"Update to version 7.0.33, 8.0.20 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-06/");
  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-05/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
