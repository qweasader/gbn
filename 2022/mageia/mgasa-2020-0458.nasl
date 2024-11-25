# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0458");
  script_cve_id("CVE-2019-15947", "CVE-2020-14198");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-09-15 13:52:12 +0000 (Tue, 15 Sep 2020)");

  script_name("Mageia: Security Advisory (MGASA-2020-0458)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0458");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0458.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27731");
  script_xref(name:"URL", value:"https://security.gentoo.org/glsa/202009-18");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bitcoin' package(s) announced via the MGASA-2020-0458 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in Bitcoin.

In Bitcoin Core 0.18.0, bitcoin-qt stores wallet.dat data unencrypted
in memory. Upon a crash, it may dump a core file. If a user were to
mishandle a core file, an attacker can reconstruct the user's
wallet.dat file, including their private keys, via a grep '6231 0500'
command (CVE-2019-15947).

Bitcoin Core 0.20.0 allows remote denial of service (CVE-2020-14198).");

  script_tag(name:"affected", value:"'bitcoin' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"bitcoin", rpm:"bitcoin~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bitcoin-qt", rpm:"bitcoin-qt~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bitcoind", rpm:"bitcoind~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bitcoinconsensus-devel", rpm:"lib64bitcoinconsensus-devel~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bitcoinconsensus0", rpm:"lib64bitcoinconsensus0~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbitcoinconsensus-devel", rpm:"libbitcoinconsensus-devel~0.20.1~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbitcoinconsensus0", rpm:"libbitcoinconsensus0~0.20.1~1.mga7", rls:"MAGEIA7"))) {
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
