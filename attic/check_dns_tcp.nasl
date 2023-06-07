###############################################################################
# OpenVAS Vulnerability Test
#
# DNS Server on UDP and TCP
#
# Authors:
# Michel Arboi <mikhail@nessus.org>
#
# Copyright:
# Copyright (C) 2005 Michel Arboi
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

# This is not really a security check.
# See STD0013

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.18356");
  script_version("2020-11-10T05:40:09+0000");
  script_tag(name:"last_modification", value:"2020-11-10 05:40:09 +0000 (Tue, 10 Nov 2020)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("DNS Server on UDP and TCP");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Michel Arboi");
  script_family("Service detection");

  script_tag(name:"summary", value:"A DNS server is running on this port but
  it only answers to UDP requests. This means that TCP requests are blocked by a firewall.

  This configuration is incorrect: TCP might be used by any request, it is not restricted
  to zone transfers. Read RFC1035 or STD0013 for more information.

  This VT has been deprecated (without any replacement) because it doesn't impose a
  security risk.");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
