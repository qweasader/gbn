# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0202");
  script_cve_id("CVE-2014-3121");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:08+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:08 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");

  script_name("Mageia: Security Advisory (MGASA-2014-0202)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0202");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0202.html");
  script_xref(name:"URL", value:"http://dist.schmorp.de/rxvt-unicode/Changes");
  script_xref(name:"URL", value:"http://openwall.com/lists/oss-security/2014/05/01/8");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=13299");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rxvt-unicode' package(s) announced via the MGASA-2014-0202 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated rxvt-unicode package fixes security vulnerability:

rxvt-unicode (aka urxvt) before 9.20 is vulnerable to a user-assisted
arbitrary commands execution issue. This can be exploited by the unprocessed
display of certain escape sequences in a crafted text file or program output.
Arbitrary command sequences can be constructed using this, and unintentionally
executed if used in conjunction with various other escape sequences
(CVE-2014-3121).");

  script_tag(name:"affected", value:"'rxvt-unicode' package(s) on Mageia 3, Mageia 4.");

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

if(release == "MAGEIA3") {

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.20~1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "MAGEIA4") {

  if(!isnull(res = isrpmvuln(pkg:"rxvt-unicode", rpm:"rxvt-unicode~9.20~1.mga4", rls:"MAGEIA4"))) {
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
