# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.94134");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2013-11-20 14:48:11 +0100 (Wed, 20 Nov 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschränken (Windows)");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04098.html");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("IT-Grundschutz-deprecated");

  script_tag(name:"summary", value:"IT-Grundschutz M4.098: Kommunikation durch Paketfilter auf Minimum beschränken (Windows).

  ACHTUNG: Dieser Test wird nicht mehr unterstützt. Er wurde ersetzt durch
  den entsprechenden Test der nun permanent and die aktuelle EL angepasst
  wird: OID 1.3.6.1.4.1.25623.1.0.94213

  Stand: 13. Ergänzungslieferung (13. EL).

  Hinweis:

  Getestet wird auf die Microsoft Windows Firewall. Für Vista und Windows 7
  auf jegliche Firewall die sich systemkonform installiert.");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
