# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885392");
  script_version("2024-09-05T12:18:34+0000");
  script_cve_id("CVE-2023-47038");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-05 12:18:34 +0000 (Thu, 05 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-29 22:46:00 +0000 (Fri, 29 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-12-06 02:14:51 +0000 (Wed, 06 Dec 2023)");
  script_name("Fedora: Security Advisory for perl (FEDORA-2023-c67f4dbf13)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c67f4dbf13");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/GNEEWAACXQCEEAKSG7XX2D5YDRWLCIZJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'perl'
  package(s) announced via the FEDORA-2023-c67f4dbf13 advisory.
Note: This VT has been deprecated as a duplicate.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Perl is a high-level programming language with roots in C, sed, awk and shell
scripting. Perl is good at handling processes and files, and is especially
good at handling text. Perl&#39, s hallmarks are practicality and efficiency.
While it is used to do a lot of different things, Perl&#39, s most common
applications are system administration utilities and web programming.

If you need only a specific feature, you can install a specific package
instead. E.g. to handle Perl scripts with /usr/bin/perl interpreter,
install perl-interpreter package. See perl-interpreter description for more
details on the Perl decomposition into packages.");

  script_tag(name:"affected", value:"'perl' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

exit(0);
}

exit(66);
