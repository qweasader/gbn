# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0356");
  script_cve_id("CVE-2020-15396", "CVE-2020-15397");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-18 19:15:00 +0000 (Fri, 18 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0356)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0356");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0356.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27170");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/J52QFVREJWJ35YSEEDDRMZQ2LM2H2WE6/");
  script_xref(name:"URL", value:"https://hylafax.sourceforge.io/news/7.0.3.php");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'hylafax+' package(s) announced via the MGASA-2020-0356 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In HylaFAX+ through 7.0.2, the faxsetup utility calls chown on files in
user-owned directories. By winning a race, a local attacker could use this to
escalate his privileges to root (CVE-2020-15396).

HylaFAX+ through 7.0.2 has scripts that execute binaries from directories
writable by unprivileged users (e.g., locations under /var/spool/hylafax that
are writable by the uucp account). This allows these users to execute code in
the context of the user calling these binaries (often root) (CVE-2020-15397).

The hylafax+ package has been updated to version 7.0.3, fixing thesee issues
and several other bugs.");

  script_tag(name:"affected", value:"'hylafax+' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"hylafax+", rpm:"hylafax+~7.0.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"hylafax+-client", rpm:"hylafax+-client~7.0.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hylafax+-devel", rpm:"lib64hylafax+-devel~7.0.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64hylafax+7", rpm:"lib64hylafax+7~7.0.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhylafax+-devel", rpm:"libhylafax+-devel~7.0.3~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libhylafax+7", rpm:"libhylafax+7~7.0.3~1.mga7", rls:"MAGEIA7"))) {
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
