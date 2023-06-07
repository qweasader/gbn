###############################################################################
# OpenVAS Vulnerability Test
#
# WorldClient for MDaemon Server Detection
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
# Erik Anderson <eanders@carmichaelsecurity.com>
# Currently no testing scripts for WorldClient vulnerabilities.  Added
# notes of the current list of WorldClient vulnerabilities
#
# Copyright:
# Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
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
  script_oid("1.3.6.1.4.1.25623.1.0.10745");
  script_version("2022-06-28T10:11:01+0000");
  script_tag(name:"last_modification", value:"2022-06-28 10:11:01 +0000 (Tue, 28 Jun 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-2000-0660");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("WorldClient for MDaemon Server Detection");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2005 Noam Rathaus <noamr@securiteam.com> & SecuriTeam");
  script_family("Web application abuses");

  script_xref(name:"URL", value:"http://www.securiteam.com/cgi-bin/htsearch?config=htdigSecuriTeam&words=WorldClient");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/1462");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2478");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4687");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/4689");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/823");

  script_tag(name:"solution", value:"Make sure all usernames and passwords are adequately long and
  that only authorized networks have access to this web server's port number
  (block the web server's port number on your firewall).");

  script_tag(name:"summary", value:"We detected the remote web server is
  running WorldClient for MDaemon. This web server enables attackers
  with the proper username and password combination to access locally
  stored mailboxes.

  In addition, earlier versions of WorldClient suffer from buffer overflow
  vulnerabilities, and web traversal problems (if those are found the Risk
  factor is higher).");

  script_tag(name:"solution_type", value:"Mitigation");
  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
