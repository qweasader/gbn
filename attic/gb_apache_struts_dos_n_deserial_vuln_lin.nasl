# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.812321");
  script_version("2022-04-13T07:21:45+0000");
  script_cve_id("CVE-2017-15707", "CVE-2017-7525");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-02-25 21:56:00 +0000 (Thu, 25 Feb 2021)");
  script_tag(name:"creation_date", value:"2017-12-05 11:48:05 +0530 (Tue, 05 Dec 2017)");
  script_name("Apache Struts 'REST' Plugin Multiple Vulnerabilities (S2-054, S2-055) - Linux");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-054");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/102021");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/99623");
  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-055");

  script_tag(name:"summary", value:"Apache Struts is prone multiple vulnerabilities.

  This VT has been merged into the VT 'Apache Struts 'REST' Plugin Multiple
  Vulnerabilities (S2-054, S2-055)' (OID: 1.3.6.1.4.1.25623.1.0.812320).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - An error in 'REST' plugin which is using an outdated JSON-lib library and is not
  handling malicious request with specially crafted JSON payload properly.

  - An error in the latest Jackson JSON library.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker to
  perform a denial of service (DoS) attack or execute arbitrary code in the context of the
  affected application.");

  script_tag(name:"affected", value:"Apache Struts 2.5 through 2.5.14.");

  script_tag(name:"solution", value:"Update to version 2.5.14.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);