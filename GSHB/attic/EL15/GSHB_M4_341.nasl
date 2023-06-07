###############################################################################
# OpenVAS Vulnerability Test
#
# IT-Grundschutz, 14. EL, Manahme 4.341
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.94246");
  script_version("2022-06-03T10:31:54+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:31:54 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.341: Integrittsschutz ab Windows Vista");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04341.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");

  script_tag(name:"summary", value:"IT-Grundschutz M4.341: Integrittsschutz ab Windows Vista.

  Stand: 14. Ergnzungslieferung (14. EL).

  Hinweis:

  Soweit technisch mglich umgesetzt (aktiviertes UAC und geschtzter Modus in verschiedenen Zonen).");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);
