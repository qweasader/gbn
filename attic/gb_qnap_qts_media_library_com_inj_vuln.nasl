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

CPE = "cpe:/o:qnap:qts";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.811772");
  script_version("2022-06-03T02:11:58+0000");
  script_tag(name:"last_modification", value:"2022-06-03 02:11:58 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2017-09-19 09:42:48 +0530 (Tue, 19 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_cve_id("CVE-2017-13067");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS 'Media Library' Command injection Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");

  script_tag(name:"summary", value:"QNAP QTS is prone to a command execution vulnerability.

  This NVT was deprecated since it is a duplicate of QNAP NAS 'Media Library' Command Execution
  Vulnerability (OID: 1.3.6.1.4.1.25623.1.0.811727)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists due to some error in the
  'QTS Media Library' using a transcoding service on port 9251.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute
  arbitrary commands on the target system.");

  script_tag(name:"affected", value:"QNAP QTS 4.2.x prior to 4.2.6 build 20170905 and
  4.3.x prior to 4.3.3.0299 build 20170901.");

  script_tag(name:"solution", value:"Upgrade to QNAP QTS 4.2.6 build 20170905 or
  4.3.3.0299 build 20170901.");

  script_xref(name:"URL", value:"https://www.qnap.com/en-uk/support/con_show.php?cid=129");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
