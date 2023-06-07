###############################################################################
# OpenVAS Vulnerability Test
#
# On Cambium Networks cnPilot Detect (SNMP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.140186");
  script_version("2020-07-29T14:12:09+0000");
  script_tag(name:"last_modification", value:"2020-07-29 14:12:09 +0000 (Wed, 29 Jul 2020)");
  script_tag(name:"creation_date", value:"2017-03-14 17:03:28 +0100 (Tue, 14 Mar 2017)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Cambium Networks cnPilot Detect (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of Cambium Networks cnPilot.

  This VT has been replaced by VT 'Cambium Networks cnPilot Detection' (OID: 1.3.6.1.4.1.25623.1.0.140629).");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Product detection");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
