###############################################################################
# OpenVAS Vulnerability Test
#
# MySQL Authentication bypass through a zero-length password
#
# Authors:
# Eli Kara <elik@beyondsecurity.com>
#
# Copyright:
# Copyright (C) 2005 Beyond Security
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
  script_oid("1.3.6.1.4.1.25623.1.0.12639");
  script_version("2023-03-01T10:20:05+0000");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10654");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/10655");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"2023-03-01 10:20:05 +0000 (Wed, 01 Mar 2023)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_name("MySQL 'zero-length password' Authentication Bypass Vulnerability (MySQL Protocol)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2005 Beyond Security");
  script_family("Default Accounts");

  script_tag(name:"summary", value:"It is possible to bypass password authentication for a database
  user using a crafted authentication packet with a zero-length password

  Note: In order to use this script, the MySQL daemon has to allow connection from the
  scanning IP address");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
