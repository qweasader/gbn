# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885413");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2023-47038");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 22:46:00 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-06 02:15:04 +0000 (Wed, 06 Dec 2023)");
  script_name("Fedora: Security Advisory for polymake (FEDORA-2023-c67f4dbf13)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c67f4dbf13");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TKH5MQLFFZDJD43O7NDRVFCZBHOJ7BWR");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polymake'
  package(s) announced via the FEDORA-2023-c67f4dbf13 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Polymake is a tool to study the combinatorics and the geometry of convex
polytopes and polyhedra.  It is also capable of dealing with simplicial
complexes, matroids, polyhedral fans, graphs, tropical objects, and so
forth.

Polymake can use various computational packages if they are installed.
Those available from Fedora are: 4ti2, azove, gfan, latte-integrale,
normaliz, qhull, Singular, TOPCOM, and vinci.

Polymake can interface with various visualization packages if they are
installed.  Install one or more of the tools from the following list:
evince, geomview, graphviz, gv, and okular.");

  script_tag(name:"affected", value:"'polymake' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
