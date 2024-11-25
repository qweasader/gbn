# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.886390");
  script_cve_id("CVE-2024-21795", "CVE-2024-21812", "CVE-2024-22097", "CVE-2024-23305", "CVE-2024-23310", "CVE-2024-23313", "CVE-2024-23606", "CVE-2024-23809");
  script_tag(name:"creation_date", value:"2024-04-03 01:16:10 +0000 (Wed, 03 Apr 2024)");
  script_version("2024-09-13T05:05:46+0000");
  script_tag(name:"last_modification", value:"2024-09-13 05:05:46 +0000 (Fri, 13 Sep 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-20 16:15:10 +0000 (Tue, 20 Feb 2024)");

  script_name("Fedora: Security Advisory (FEDORA-2024-ff6a72d8e9)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC40");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-ff6a72d8e9");
  script_xref(name:"URL", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-ff6a72d8e9");
  script_xref(name:"URL", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2264832");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'biosig4c++' package(s) announced via the FEDORA-2024-ff6a72d8e9 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"### 2.6.0 - Security Update

#### BrainVisionMarker
- fixes [CVE-2024-23305]([link moved to references])
#### BrainVision: proved parser and sanity checks
- fixes [CVE-2024-22097]([link moved to references]), [CVE-2024-23809]([link moved to references])
#### EGI
- fixes [CVE-2024-21795]([link moved to references])
#### FAMOS: disabled, support can be enabled by setting `BIOSIG_FAMOS_TRUST_INPUT=1`
- mitigate vulnerabilities [CVE-2024-21812]([link moved to references]), [CVE-2024-23313]([link moved to references]), [CVE-2024-23310]([link moved to references]), [CVE-2024-23606]([link moved to references])");

  script_tag(name:"affected", value:"'biosig4c++' package(s) on Fedora 40.");

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

  if(!isnull(res = isrpmvuln(pkg:"biosig4c++", rpm:"biosig4c++~2.6.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"biosig4c++-debuginfo", rpm:"biosig4c++-debuginfo~2.6.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"biosig4c++-debugsource", rpm:"biosig4c++-debugsource~2.6.0~3.fc40", rls:"FC40"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"biosig4c++-devel", rpm:"biosig4c++-devel~2.6.0~3.fc40", rls:"FC40"))) {
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
