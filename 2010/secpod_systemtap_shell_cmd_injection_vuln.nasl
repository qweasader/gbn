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
  script_oid("1.3.6.1.4.1.25623.1.0.902017");
  script_version("2022-02-18T13:05:59+0000");
  script_tag(name:"last_modification", value:"2022-02-18 13:05:59 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2010-02-02 07:26:26 +0100 (Tue, 02 Feb 2010)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4273");
  script_name("SystemTap 'stap-server' Remote Shell Command Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_systemtap_detect.nasl");
  script_family("General");
  script_mandatory_keys("SystemTap/Ver");

  script_xref(name:"URL", value:"http://secunia.com/advisories/38154");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0169");

  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to inject
  and execute malicious shell commands or compromise a system.");

  script_tag(name:"affected", value:"SystemTap versions prior to 1.1.");

  script_tag(name:"insight", value:"The flaw is due to input validation error in the 'stap-server'
  component when processing user-supplied requests.");

  script_tag(name:"solution", value:"Update to version 1.1 or later.");

  script_tag(name:"summary", value:"SystemTap is prone to an arbitrary command execution
  vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

if(!vers = get_kb_item("SystemTap/Ver"))
  exit(0);

if(version_is_less(version:vers, test_version:"1.1")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"1.1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
