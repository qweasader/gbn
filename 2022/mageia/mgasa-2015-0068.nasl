# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2015.0068");
  script_cve_id("CVE-2014-9637", "CVE-2015-1196", "CVE-2015-1395");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-08-30 01:13:00 +0000 (Wed, 30 Aug 2017)");

  script_name("Mageia: Security Advisory (MGASA-2015-0068)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA4");

  script_xref(name:"Advisory-ID", value:"MGASA-2015-0068");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2015-0068.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=15142");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-January/148953.html");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2015-February/149140.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'patch' package(s) announced via the MGASA-2015-0068 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated patch package fixes security vulnerabilities:

It was reported that a crafted diff file can make patch eat memory and later
segfault (CVE-2014-9637).

It was reported that the versions of the patch utility that support Git-style
patches are vulnerable to a directory traversal flaw. This could allow an
attacker to overwrite arbitrary files by applying a specially crafted patch,
with the privileges of the user running patch (CVE-2015-1395).

GNU patch before 2.7.4 allows remote attackers to write to arbitrary files via
a symlink attack in a patch file (CVE-2015-1196).");

  script_tag(name:"affected", value:"'patch' package(s) on Mageia 4.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"patch", rpm:"patch~2.7.4~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
