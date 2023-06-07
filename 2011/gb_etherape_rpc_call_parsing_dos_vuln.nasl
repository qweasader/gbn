###############################################################################
# OpenVAS Vulnerability Test
#
# EtherApe RPC Packet Processing Denial of Service Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (C) 2011 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802340");
  script_version("2022-02-17T14:14:34+0000");
  script_cve_id("CVE-2011-3369");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-02-17 14:14:34 +0000 (Thu, 17 Feb 2022)");
  script_tag(name:"creation_date", value:"2011-11-08 17:22:20 +0530 (Tue, 08 Nov 2011)");
  script_name("EtherApe RPC Packet Processing Denial of Service Vulnerability");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to cause a NULL pointer
  dereference or cause a denial of service.");

  script_tag(name:"affected", value:"EtherApe version prior to 0.9.12.");

  script_tag(name:"insight", value:"The flaw is due to an error in the add_conversation function in
  'conversations.c' when processing specially crafted RPC packet.");

  script_tag(name:"solution", value:"Upgrade to EtherApe version 0.9.12 or later.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"EtherApe is prone to denial of service vulnerabilities.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/45989");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/09/19/4");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2011/09/22/1");
  script_xref(name:"URL", value:"http://sourceforge.net/tracker/?func=detail&aid=3309061&group_id=2712&atid=102712");

  exit(0);
}

include("ssh_func.inc");
include("version_func.inc");

sock = ssh_login_or_reuse_connection();
if(!sock)
  exit(0);

etherapeName = ssh_find_file(file_name:"/etherape$", useregex:TRUE, sock:sock);

foreach binaryName (etherapeName) {

  binaryName = chomp(binaryName);
  if(!binaryName)
    continue;

  etherVer = ssh_get_bin_version(full_prog_name:binaryName, version_argv:"--version", ver_pattern:"GNOME EtherApe ([0-9.]+)", sock:sock);

  if(etherVer[1]) {
    if(version_is_less(version:etherVer[1], test_version:"0.9.12")) {
      report = report_fixed_ver(installed_version:etherVer[1], fixed_version:"0.9.12");
      security_message(port:0, data:report);
      ssh_close_connection();
      exit(0);
    }
  }
}

ssh_close_connection();
exit(0);
