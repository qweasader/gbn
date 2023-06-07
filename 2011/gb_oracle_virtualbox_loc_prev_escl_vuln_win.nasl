# Copyright (C) 2011 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.801578");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-01-27 07:47:27 +0100 (Thu, 27 Jan 2011)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2010-4414");
  script_name("Oracle VM VirtualBox Extensions Local Privilege Escalation Vulnerability - Windows");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("secpod_sun_virtualbox_detect_win.nasl");
  script_mandatory_keys("Oracle/VirtualBox/Win/Ver");

  script_xref(name:"URL", value:"https://www.oracle.com/security-alerts/cpujan2011.html#AppendixSUNS");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/45876");

  script_tag(name:"impact", value:"Successful exploitation will let the local users gain
  escalated privileges.");

  script_tag(name:"affected", value:"Oracle VirtualBox version 4.0.");

  script_tag(name:"insight", value:"The flaw is caused by an unspecified error related to various
  extensions, which could allow local authenticated attackers to gain elevated privileges.");

  script_tag(name:"summary", value:"Oracle VirtualBox is prone to a local privilege escalation
  vulnerability.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for
  more information.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("Oracle/VirtualBox/Win/Ver"))
  exit(0);

if(version_is_equal(version:vers, test_version:"4.0")) {
  report = report_fixed_ver(installed_version:vers, vulnerable_range:"Equal to 4.0");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);