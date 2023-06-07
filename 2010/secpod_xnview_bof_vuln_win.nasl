# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900752");
  script_version("2022-05-02T09:35:37+0000");
  script_tag(name:"last_modification", value:"2022-05-02 09:35:37 +0000 (Mon, 02 May 2022)");
  script_tag(name:"creation_date", value:"2010-03-30 16:15:33 +0200 (Tue, 30 Mar 2010)");
  script_cve_id("CVE-2009-4001");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_name("XnView DICOM Parsing Integer Overflow Vulnerability (Windows)");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_dependencies("secpod_xnview_detect_win.nasl");
  script_mandatory_keys("XnView/Win/Ver");

  script_tag(name:"summary", value:"XnView is prone to an integer overflow vulnerability.");

  script_tag(name:"insight", value:"The flaw is due to an integer overflow when processing DICOM images with
  certain dimensions. This can be exploited to cause a heap-based buffer
  overflow by persuading a victim to open a specially-crafted DICOM image
  file.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to cause a buffer overflow and execute
  arbitrary code on the system with elevated privileges or cause the
  application to crash.");

  script_tag(name:"affected", value:"XnView versions prior to 1.97.2 on Windows");

  script_tag(name:"solution", value:"Update to XnView version 1.97.2");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/56802");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38629");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/509999/100/0/threaded");

  exit(0);
}

include("version_func.inc");

if(!version = get_kb_item("XnView/Win/Ver"))
  exit(0);

if(version_is_less(version:version, test_version:"1.97.2")) {
  report = report_fixed_ver(installed_version:version, fixed_version:"1.97.2");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);
