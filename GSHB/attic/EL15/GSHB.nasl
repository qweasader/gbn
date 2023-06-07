##############################################################################
# OpenVAS Vulnerability Test
#
# IT-Grundschutz, 14. Ergnzungslieferung
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Modified:
# Emanuel Moss <emanuel.moss@greenbone.net>
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
  script_oid("1.3.6.1.4.1.25623.1.0.94171");
  script_version("2022-06-03T10:31:54+0000");
  script_tag(name:"last_modification", value:"2022-06-03 10:31:54 +0000 (Fri, 03 Jun 2022)");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz, 15. EL");
  # Dependencies GSHB_M4_007.nasl and GSHB_M4_094.nasl are running in ACT_ATTACK because these depends on
  # GSHB_SSH_TELNET_BruteForce.nasl / GSHB_nikto.nasl which are in ACT_ATTACK as well.
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Compliance");

  script_tag(name:"summary", value:"Zusammenfassung von Tests gem der IT-Grundschutz Kataloge
  mit Stand 15. Ergnzungslieferung.

  Diese Routinen prfen smtliche Manahmen des IT-Grundschutz des Bundesamts fr Sicherheit
  in der Informationstechnik (BSI) auf den Zielsystemen soweit die Manahmen auf automatisierte
  Weise abgeprft werden knnen.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);