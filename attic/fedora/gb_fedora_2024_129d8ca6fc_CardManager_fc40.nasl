# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886101");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2024-1938", "CVE-2024-1939");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"creation_date", value:"2024-03-08 02:18:44 +0000 (Fri, 08 Mar 2024)");
  script_name("Fedora: Security Advisory for CardManager (FEDORA-2024-129d8ca6fc)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-129d8ca6fc");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3TLXYOFRPJZKZHWYZES6KGK5TBUPNJX6");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'CardManager'
  package(s) announced via the FEDORA-2024-129d8ca6fc advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This is free, open source multiplatform (java) application which allows you to
 play ANY card game.
The game is designed especially to play collectible card games like Magic the
 Gathering or Doomtrooper over network.
To play those games you need to own (scanned) images of card, which are not part
 of this package.
Some can be easily downloadable from internet, but be aware of copyrights.
The default deck and background is free of copyright
Also please feel free to add your own backgrounds to
~/CardManager/data/backgrounds and of course enhance
collection under ~/CardManager/collection");

  script_tag(name:"affected", value:"'CardManager' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
