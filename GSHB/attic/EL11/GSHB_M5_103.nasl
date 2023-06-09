###############################################################################
# OpenVAS Vulnerability Test
#
# IT-Grundschutz, 11. EL, Massnahme 5.103
#
# Authors:
# Thomas Rotter <T.Rotter@dn-systems.de>
#
# Copyright:
# Copyright (C) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.895103");
  script_version("2020-08-04T13:27:06+0000");
  script_tag(name:"last_modification", value:"2020-08-04 13:27:06 +0000 (Tue, 04 Aug 2020)");
  script_tag(name:"creation_date", value:"2010-01-14 14:29:35 +0100 (Thu, 14 Jan 2010)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz (Windows)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-deprecated");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05103.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.103: Entfernen saemtlicher Netzwerkfreigaben beim IIS-Einsatz (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstuetzt. Er wurde zudem in neueren
  EL gestrichen.

  Diese Pruefung bezieht sich auf die 11. Ergaenzungslieferung (11. EL) des IT-
  Grundschutz. Die detaillierte Beschreibung zu dieser Massnahme findet sich unter
  nachfolgendem Verweis. Es ist zu beachten, dass der dortige Text sich immer auf
  die aktuellste Ergaenzungslieferung bezieht. Titel und Inhalt koennen sich bei einer
  Aktualisierung aendern, allerdings nicht die Kernthematik.");

  script_tag(name:"qod_type", value:"general_note");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
