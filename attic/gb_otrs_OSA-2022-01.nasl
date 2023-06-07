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
  script_oid("1.3.6.1.4.1.25623.1.0.126178");
  script_version("2022-10-25T10:13:35+0000");
  script_tag(name:"last_modification", value:"2022-10-25 10:13:35 +0000 (Tue, 25 Oct 2022)");
  script_tag(name:"creation_date", value:"2022-10-19 11:20:57 +0000 (Wed, 19 Oct 2022)");
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-14 20:40:00 +0000 (Mon, 14 Feb 2022)");

  script_cve_id("CVE-2022-0473");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OTRS XSS Vulnerability (OSA-2022-01)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"OTRS is prone to a cross-site scripting (XSS) vulnerability.

  This VT has been deprecated as a duplicate of the VT 'OTRS XSS Vulnerability (OSA-2022-01)'
  (OID:1.3.6.1.4.1.25623.1.0.147601).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"OTRS administrators can configure dynamic field and inject
  malicious JavaScript code in the error message of the regular expression check. When used in the
  agent interface, malicious code might be executed in the browser.");

  script_tag(name:"affected", value:"OTRS version 7.0.x through 7.0.31.");

  script_tag(name:"solution", value:"Update to version 7.0.32 or later.");

  script_xref(name:"URL", value:"https://otrs.com/release-notes/otrs-security-advisory-2022-01/");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
