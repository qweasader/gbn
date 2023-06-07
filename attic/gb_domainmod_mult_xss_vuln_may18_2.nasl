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
  script_oid("1.3.6.1.4.1.25623.1.0.113329");
  script_version("2021-09-20T15:26:26+0000");
  script_tag(name:"last_modification", value:"2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)");
  script_tag(name:"creation_date", value:"2019-01-23 14:38:54 +0200 (Wed, 23 Jan 2019)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-29 12:19:00 +0000 (Thu, 29 Nov 2018)");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2018-11558", "CVE-2018-11559");

  script_name("DomainMOD < 4.12.0 Multiple XSS Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"DomainMOD is prone to multiple Cross-Site Scripting (XSS) Vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - Stored XSS in the '/settings/profile/index.php' new_first_name parameter

  - Stored XSS in the '/settings/profile/index.php' new_last_name parameter");

  script_tag(name:"impact", value:"Successful exploitation would allow an authenticated attacker to inject
  arbitrary JavaScript and HTML into the page.");

  script_tag(name:"affected", value:"DomainMOD prior to version 4.12.0.");
  script_tag(name:"solution", value:"Update to DomainMOD version 4.12.0 or later.");

  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/66");
  script_xref(name:"URL", value:"https://github.com/domainmod/domainmod/issues/66#issuecomment-460099901");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

#nb: Consolidated in scripts/2019/domainmod/gb_domainmod_mult_vuln_jan19.nasl
exit(66);
