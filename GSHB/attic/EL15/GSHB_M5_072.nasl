# SPDX-FileCopyrightText: 2015 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.95068");
  script_version("2023-06-27T05:05:30+0000");
  script_tag(name:"last_modification", value:"2023-06-27 05:05:30 +0000 (Tue, 27 Jun 2023)");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.072: Deaktivieren nicht ben�tigter Netzdienste");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone AG");
  script_family("IT-Grundschutz-15");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05072.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.072: Deaktivieren nicht ben�tigter Netzdienste.

  Stand: 14. Erg�nzungslieferung (14. EL).

  Hinweis: Lediglich Anzeige der in Frage kommenden Dienste.");

  script_tag(name:"qod_type", value:"remote_active");
  script_tag(name:"deprecated", value:TRUE);
  exit(0);
}

exit(66);