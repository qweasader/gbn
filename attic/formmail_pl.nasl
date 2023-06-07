###############################################################################
# OpenVAS Vulnerability Test
#
# formmail.pl
#
# Authors:
# Mathieu Perrin <mathieu@tpfh.org>
#
# Copyright:
# Copyright (C) 2005 Mathieu Perrin
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
  script_oid("1.3.6.1.4.1.25623.1.0.10076");
  script_version("2022-04-13T07:21:45+0000");
  script_tag(name:"last_modification", value:"2022-04-13 07:21:45 +0000 (Wed, 13 Apr 2022)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/2079");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-1999-0172");
  script_name("formmail.pl");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Mathieu Perrin");
  script_family("Web application abuses");

  script_tag(name:"solution", value:"Remove it from /cgi-bin.");

  script_tag(name:"summary", value:"The 'formmail.pl' is installed. This CGI has a well known security flaw
  that lets anyone execute arbitrary commands with the privileges of the http daemon (root or nobody).");

  script_tag(name:"deprecated", value:TRUE);

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Workaround");

  exit(0);
}

exit(66); # broken
