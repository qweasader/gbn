# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.9.2023.1998796101348");
  script_cve_id("CVE-2022-0856");
  script_tag(name:"creation_date", value:"2024-09-10 12:16:00 +0000 (Tue, 10 Sep 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-15 18:10:13 +0000 (Tue, 15 Mar 2022)");

  script_name("Fedora: Security Advisory (FEDORA-2023-19b796e348)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-19b796e348");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-19b796e348");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1701685");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081750");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libcaca' package(s) announced via the FEDORA-2023-19b796e348 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Automatic update for libcaca-0.99-0.69.beta20.fc40.

##### **Changelog**

```
* Sun Sep 24 2023 Xavier Bachelot <xavier@bachelot.org> - 0.99-0.69.beta20
- Fix CVE-2022-0856 (RHBZ#2081750)
- Add missing Requires: for caca-utils (RHBZ#1701685)

```");

  script_tag(name:"affected", value:"'libcaca' package(s) on Fedora 40.");

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

if(release == "FC40") {

  if(!isnull(res = isrpmvuln(pkg:"caca-utils", rpm:"caca-utils~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"caca-utils-debuginfo", rpm:"caca-utils-debuginfo~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca", rpm:"libcaca~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-debuginfo", rpm:"libcaca-debuginfo~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-debugsource", rpm:"libcaca-debugsource~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libcaca-devel", rpm:"libcaca-devel~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-caca", rpm:"python3-caca~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca", rpm:"ruby-caca~0.99~0.69.beta20.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"ruby-caca-debuginfo", rpm:"ruby-caca-debuginfo~0.99~0.69.beta20.fc40", rls:"FC40"))) {
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
