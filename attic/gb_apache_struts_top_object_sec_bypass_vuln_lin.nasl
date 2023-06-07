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
  script_oid("1.3.6.1.4.1.25623.1.0.811316");
  script_version("2023-01-19T10:10:48+0000");
  script_cve_id("CVE-2015-5209");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-07-01 01:29:00 +0000 (Sun, 01 Jul 2018)");
  script_tag(name:"creation_date", value:"2017-08-31 13:48:08 +0530 (Thu, 31 Aug 2017)");
  script_name("Apache Struts 'top' Object Access Security Bypass Vulnerability (S2-026) - Linux");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");

  script_xref(name:"URL", value:"https://cwiki.apache.org/confluence/display/WW/S2-026");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/82550");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id/1033908");

  script_tag(name:"summary", value:"Apache Struts is prone to a security bypass
  vulnerability.

  This VT has been merged into the VT 'Apache Struts 'top' Object Access Security Bypass
  Vulnerability (S2-026)' (OID: 1.3.6.1.4.1.25623.1.0.811315).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the
  target host.");

  script_tag(name:"insight", value:"The flaw exists due to due to an incorrect handling of
  the 'top' object in specially crafted request.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to bypass
  certain security restrictions and perform unauthorized actions. This may lead to further
  attacks.");

  script_tag(name:"affected", value:"Apache Struts 2.x before 2.3.24.1.");

  script_tag(name:"solution", value:"Update to version 2.3.24.1 or later.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
