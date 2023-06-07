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
  script_oid("1.3.6.1.4.1.25623.1.0.902474");
  script_version("2022-04-28T13:38:57+0000");
  script_cve_id("CVE-2011-3422");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-09-23 16:39:49 +0200 (Fri, 23 Sep 2011)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Apple Mac OS X Keychain Certificate Settings Security Bypass Vulnerability");
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version", re:"ssh/login/osx_version=^10\.6\.");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/69556");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49429");
  script_xref(name:"URL", value:"http://www.securitytracker.com/id?1026002");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to bypass security
  restrictions and launch further attacks on the system.");

  script_tag(name:"affected", value:"Mac OS X version 10.6 to 10.6.8

  Mac OS X Server version 10.6 to 10.6.8.");

  script_tag(name:"insight", value:"The flaw is due to an error in the implementation of Certificate
  Trust Policy, which allows attacker to bypass KeyChain security settings to accept
  an Extended Validation certificate as valid.");

  script_tag(name:"solution", value:"Upgrade to Mac OS X version 10.7.3 or later.");

  script_tag(name:"summary", value:"Mac OS X is prone to a security bypass vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName || "Mac OS X" >!< osName)
  exit(0);

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer)
  exit(0);

if(osVer =~ "^10\.6\." && version_in_range(version:osVer, test_version:"10.6.0", test_version2:"10.6.8")) {
  report = report_fixed_ver(installed_version:osVer, fixed_version:"10.7.3");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);