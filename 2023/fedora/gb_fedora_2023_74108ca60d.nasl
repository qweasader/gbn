# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884853");
  script_cve_id("CVE-2023-39350", "CVE-2023-39351", "CVE-2023-39352", "CVE-2023-39353", "CVE-2023-39354", "CVE-2023-39356", "CVE-2023-40181", "CVE-2023-40186", "CVE-2023-40188", "CVE-2023-40567", "CVE-2023-40569", "CVE-2023-40589");
  script_tag(name:"creation_date", value:"2023-09-22 01:15:55 +0000 (Fri, 22 Sep 2023)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-06 20:31:55 +0000 (Wed, 06 Sep 2023)");

  script_name("Fedora: Security Advisory (FEDORA-2023-74108ca60d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-74108ca60d");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2023-74108ca60d");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2236653");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'freerdp' package(s) announced via the FEDORA-2023-74108ca60d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Update to 2.11.1

----

Update to 2.11.0 (CVE-2023-39350, CVE-2023-39351, CVE-2023-39352, CVE-2023-39353, CVE-2023-39354, CVE-2023-39356, CVE-2023-40181, CVE-2023-40186, CVE-2023-40188, CVE-2023-40567, CVE-2023-40569 and CVE-2023-40589).");

  script_tag(name:"affected", value:"'freerdp' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"freerdp", rpm:"freerdp~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debuginfo", rpm:"freerdp-debuginfo~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-debugsource", rpm:"freerdp-debugsource~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-devel", rpm:"freerdp-devel~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs", rpm:"freerdp-libs~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-libs-debuginfo", rpm:"freerdp-libs-debuginfo~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server", rpm:"freerdp-server~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"freerdp-server-debuginfo", rpm:"freerdp-server-debuginfo~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr", rpm:"libwinpr~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-debuginfo", rpm:"libwinpr-debuginfo~2.11.1~1.fc39", rls:"FC39"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwinpr-devel", rpm:"libwinpr-devel~2.11.1~1.fc39", rls:"FC39"))) {
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
