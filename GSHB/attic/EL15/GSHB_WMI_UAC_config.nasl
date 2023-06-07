###############################################################################
# OpenVAS Vulnerability Test
#
# Read the config of the User Account Control feature over WMI (Windows)
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.96046");
  script_version("2022-06-03T10:31:54+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:31:54 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2010-01-15 16:20:21 +0100 (Fri, 15 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("Read the config of the User Account Control feature over WMI");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz");
  script_tag(name:"summary", value:"Read the config of the User Account Control feature over WMI.");
  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);

