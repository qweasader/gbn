###############################################################################
# OpenVAS Vulnerability Test
#
# Wrapper for Nmap Finger NSE script.
#
# Authors:
# NSE-Script: Eddie Bell
# NASL-Wrapper: Sooraj KS <kssooraj@secpod.com>
#
# Copyright:
# NSE-Script: The Nmap Security Scanner (http://nmap.org)
# NASL-Wrapper: Copyright (C) 2011 Greenbone Networks GmbH (http://www.greenbone.net)
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
  script_oid("1.3.6.1.4.1.25623.1.0.801685");
  script_version("2020-07-07T13:54:18+0000");
  script_tag(name:"last_modification", value:"2020-07-07 13:54:18 +0000 (Tue, 07 Jul 2020)");
  script_tag(name:"creation_date", value:"2011-01-06 14:34:14 +0100 (Thu, 06 Jan 2011)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Nmap NSE: Finger");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"remote_analysis");
  script_copyright("Copyright (C) 2011 NSE-Script: The Nmap Security Scanner; NASL-Wrapper: Greenbone Networks GmbH");
  script_family("Nmap NSE");

  script_tag(name:"summary", value:"This script attempts to retrieve a list of usernames using the finger service.

  This is a wrapper on the Nmap Security Scanner's finger.nse.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
