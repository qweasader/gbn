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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112892");
  script_version("2021-10-25T13:35:06+0000");
  script_tag(name:"last_modification", value:"2021-10-25 13:35:06 +0000 (Mon, 25 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-06-02 10:57:11 +0000 (Wed, 02 Jun 2021)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 19:40:00 +0000 (Fri, 11 Jun 2021)");

  script_cve_id("CVE-2020-10666");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FreePBX 13.x <= 13.0.93.2, 14.x <= 14.0.22.2, 15.x <= 15.0.19.2 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"FreePBX is prone to a remote code execution (RCE) vulnerability.

  NOTE: This VT is reporting a false positive and therefore has been deprecated. The vulnerability
  exists in the Restapps / Phone apps module and not in the core framework itself.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Remote execution vulnerabilities exist in the Restapps / Phone
  apps module. A URL variable could potentially get passed into an AMI command, allowing for RCE.");

  script_tag(name:"affected", value:"FreePBX 13.x through 13.0.93.2, 14.x through 14.0.22.2
  and 15.x through 15.0.19.2.");

  script_tag(name:"solution", value:"Updates are available. Please see the referenced advisory for
  more information.");

  script_xref(name:"URL", value:"https://wiki.freepbx.org/display/FOP/2020-03-12+SECURITY%3A+Potential+Rest+Phone+Apps+RCE");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
