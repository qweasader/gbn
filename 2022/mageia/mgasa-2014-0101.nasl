# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2014.0101");
  script_cve_id("CVE-2013-7322");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:N");

  script_name("Mageia: Security Advisory (MGASA-2014-0101)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA(3|4)");

  script_xref(name:"Advisory-ID", value:"MGASA-2014-0101");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2014-0101.html");
  script_xref(name:"URL", value:"http://lists.nongnu.org/archive/html/oath-toolkit-help/2013-12/msg00000.html");
  script_xref(name:"URL", value:"http://www.nongnu.org/oath-toolkit/NEWS.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=12873");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/pipermail/package-announce/2014-February/128934.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'oath-toolkit' package(s) announced via the MGASA-2014-0101 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that comments (lines starting with a hash) in /etc/users.oath
could prevent one-time-passwords (OTP) from being invalidated, leaving the OTP
vulnerable to replay attacks (CVE-2013-7322).");

  script_tag(name:"affected", value:"'oath-toolkit' package(s) on Mageia 3, Mageia 4.");

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

  if(!isnull(res = isrpmvuln(pkg:"lib64oath-devel", rpm:"lib64oath-devel~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oath0", rpm:"lib64oath0~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath-devel", rpm:"liboath-devel~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath0", rpm:"liboath0~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit", rpm:"oath-toolkit~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_oath", rpm:"pam_oath~1.12.6~2.1.mga3", rls:"MAGEIA3"))) {
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

  if(!isnull(res = isrpmvuln(pkg:"lib64oath-devel", rpm:"lib64oath-devel~2.4.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64oath0", rpm:"lib64oath0~2.4.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath-devel", rpm:"liboath-devel~2.4.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"liboath0", rpm:"liboath0~2.4.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"oath-toolkit", rpm:"oath-toolkit~2.4.1~1.mga4", rls:"MAGEIA4"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"pam_oath", rpm:"pam_oath~2.4.1~1.mga4", rls:"MAGEIA4"))) {
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
