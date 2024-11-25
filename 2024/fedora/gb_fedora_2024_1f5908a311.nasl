# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886309");
  script_cve_id("CVE-2024-1622");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:51 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-1f5908a311)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-1f5908a311");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-1f5908a311");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2266065");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/commit/f1e85a7505201524bd68fb9296e7db0752907a6f");
  script_xref(name:"URL", value:"https://github.com/NLnetLabs/routinator/pull/937");
  script_xref(name:"URL", value:"https://www.nlnetlabs.nl/downloads/routinator/CVE-2024-1622.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rust-routinator' package(s) announced via the FEDORA-2024-1f5908a311 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"from [changelog]([link moved to references]):

* Fix the RTR listener so that Routinator won't exit if an incoming RTR
 connection is closed again too quickly. ([#937], reported by Yohei
 Nishimura, Atsushi Enomoto, Ruka Miyachi, Internet Multifeed Co., Japan.
 Assigned [CVE-2024-1622].)

[#937]: [link moved to references]
[CVE-2024-1622]: [link moved to references]");

  script_tag(name:"affected", value:"'rust-routinator' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"routinator", rpm:"routinator~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"routinator-debuginfo", rpm:"routinator-debuginfo~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+arbitrary-devel", rpm:"rust-routinator+arbitrary-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+aspa-devel", rpm:"rust-routinator+aspa-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+default-devel", rpm:"rust-routinator+default-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+native-tls-devel", rpm:"rust-routinator+native-tls-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+routinator-ui-devel", rpm:"rust-routinator+routinator-ui-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+rta-devel", rpm:"rust-routinator+rta-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+socks-devel", rpm:"rust-routinator+socks-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+tls-devel", rpm:"rust-routinator+tls-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator+ui-devel", rpm:"rust-routinator+ui-devel~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator", rpm:"rust-routinator~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-debugsource", rpm:"rust-routinator-debugsource~0.13.2~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"rust-routinator-devel", rpm:"rust-routinator-devel~0.13.2~1.fc39", rls:"FC39"))) {
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
