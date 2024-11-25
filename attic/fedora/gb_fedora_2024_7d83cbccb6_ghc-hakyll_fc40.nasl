# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886347");
  script_version("2024-09-05T12:18:35+0000");
  script_cve_id("CVE-2023-35936", "CVE-2023-38745");
  script_tag(name:"cvss_base", value:"5.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:35 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-03 13:43:26 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"creation_date", value:"2024-03-29 02:11:33 +0000 (Fri, 29 Mar 2024)");
  script_name("Fedora: Security Advisory for ghc-hakyll (FEDORA-2024-7d83cbccb6)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-7d83cbccb6");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OORR4QKNT3ZG6UCRUAOVGXU3QX42MWFF");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ghc-hakyll'
  package(s) announced via the FEDORA-2024-7d83cbccb6 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hakyll is a static website compiler library. It provides you with the tools to
create a simple or advanced static website using a Haskell DSL and formats such as markdown or RST.");

  script_tag(name:"affected", value:"'ghc-hakyll' package(s) on Fedora 40.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
