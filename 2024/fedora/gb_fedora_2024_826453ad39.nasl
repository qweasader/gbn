# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886312");
  script_cve_id("CVE-2024-1481");
  script_tag(name:"creation_date", value:"2024-03-25 09:38:53 +0000 (Mon, 25 Mar 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Fedora: Security Advisory (FEDORA-2024-826453ad39)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-826453ad39");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-826453ad39");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2265129");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freeipa' package(s) announced via the FEDORA-2024-826453ad39 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"- Security release: CVE-2024-1481
- Resolves: rhbz#2265129");

  script_tag(name:"affected", value:"'freeipa' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"freeipa", rpm:"freeipa~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client", rpm:"freeipa-client~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-common", rpm:"freeipa-client-common~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-debuginfo", rpm:"freeipa-client-debuginfo~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-epn", rpm:"freeipa-client-epn~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-client-samba", rpm:"freeipa-client-samba~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-common", rpm:"freeipa-common~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-debuginfo", rpm:"freeipa-debuginfo~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-debugsource", rpm:"freeipa-debugsource~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-python-compat", rpm:"freeipa-python-compat~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-selinux", rpm:"freeipa-selinux~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server", rpm:"freeipa-server~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-common", rpm:"freeipa-server-common~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-debuginfo", rpm:"freeipa-server-debuginfo~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-dns", rpm:"freeipa-server-dns~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-trust-ad", rpm:"freeipa-server-trust-ad~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freeipa-server-trust-ad-debuginfo", rpm:"freeipa-server-trust-ad-debuginfo~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipaclient", rpm:"python3-ipaclient~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipalib", rpm:"python3-ipalib~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipaserver", rpm:"python3-ipaserver~4.11.1~2.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-ipatests", rpm:"python3-ipatests~4.11.1~2.fc39", rls:"FC39"))) {
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
