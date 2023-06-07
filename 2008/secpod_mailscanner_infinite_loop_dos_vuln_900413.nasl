# Copyright (C) 2008 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.900413");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-12-10 08:20:26 +0100 (Wed, 10 Dec 2008)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_copyright("Copyright (C) 2008 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Denial of Service");
  script_name("MailScanner Infinite Loop DoS Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/Advisories/32915");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32514");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary
  codes in a crafted message and it can lead to system crash through high CPU resources.");

  script_tag(name:"affected", value:"MailScanner version prior to 4.73.3-1.");

  script_tag(name:"insight", value:"This error is due to an issue in 'Clean' Function in
  message.pm.");

  script_tag(name:"solution", value:"Update to version 4.73.3-1 or later.");

  script_tag(name:"summary", value:"MailScanner is prone to a denial of service (DoS) vulnerability.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

if(!sock = ssh_login_or_reuse_connection())
  exit(0);

ver = ssh_cmd(socket:sock, cmd:"MailScanner -v", timeout:120);
ssh_close_connection();

if("MailScanner" >!< ver)
  exit(0);

pattern = "MailScanner version ([0-3](\..*)|4(\.[0-6]?[0-9](\..*)?|\.7[0-2](\..*)?|\.73\.[0-3]))($|[^.0-9])";
if(found = egrep(pattern:pattern, string:ver)) {
  report = report_fixed_ver(installed_version:chomp(found), fixed_version:"4.73.3-1");
  security_message(port:0, data:report);
  exit(0);
}

exit(99);
