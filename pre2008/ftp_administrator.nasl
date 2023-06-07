# OpenVAS Vulnerability Test
# Description: Windows Administrator NULL FTP password
#
# Authors:
# Keith Young <Keith.Young@co.mo.md.us>
#
# Copyright:
# Copyright (C) 2002 Keith Young
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.11160");
  script_version("2020-08-24T08:40:10+0000");
  script_tag(name:"last_modification", value:"2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:P");
  script_name("Windows Administrator NULL FTP password");
  script_category(ACT_ATTACK);
  script_family("FTP");
  script_copyright("Copyright (C) 2002 Keith Young");
  script_dependencies("ftpserver_detect_type_nd_version.nasl", "DDI_FTP_Any_User_Login.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ftp", 21);
  script_mandatory_keys("ftp/banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_tag(name:"solution", value:"Change the Administrator password on this host.");

  script_tag(name:"summary", value:"The remote server is incorrectly configured
  with a NULL password for the user 'Administrator' and has FTP enabled.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ftp_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ftp_get_port(default:21);

if(!ftp_get_banner(port:port))
  exit(0);

if(ftp_broken_random_login(port:port))
  exit(0);

if(!soc = ftp_open_socket(port:port))
  exit(0);

if(ftp_authenticate(socket:soc, user:"Administrator", pass:"", skip_banner:TRUE)) {
  security_message(port:port);
  ftp_close(socket:soc);
  exit(0);
}

ftp_close(socket:soc);
exit(0);
