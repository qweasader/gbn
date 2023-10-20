# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0040");
  script_cve_id("CVE-2020-15117");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-12-17 03:15:00 +0000 (Thu, 17 Dec 2020)");

  script_name("Mageia: Security Advisory (MGASA-2021-0040)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0040");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0040.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27851");
  script_xref(name:"URL", value:"https://github.com/symless/synergy-core/security/advisories/GHSA-chfm-333q-gfpp");
  script_xref(name:"URL", value:"https://github.com/symless/synergy-core/releases/tag/1.11.0-stable");
  script_xref(name:"URL", value:"https://github.com/symless/synergy-core/releases/tag/v1.11.1-stable");
  script_xref(name:"URL", value:"https://github.com/symless/synergy-core/releases/tag/v1.12.0-stable");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VFDEQED64YLWQK2TF73EMXZDYX7YT2DD/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'synergy' package(s) announced via the MGASA-2021-0040 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In Synergy before version 1.12.0, a Synergy server can be crashed by receiving
a kMsgHelloBack packet with a client name length set to 0xffffffff (4294967295)
if the servers memory is less than 4 GB. It was verified that this issue does
not cause a crash through the exception handler if the available memory of the
Server is more than 4GB (CVE-2020-15117).

The synergy package has been updated to version 1.12.0, fixing this issue and
several other bugs.");

  script_tag(name:"affected", value:"'synergy' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"synergy", rpm:"synergy~1.12.0~1.mga7", rls:"MAGEIA7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"synergy-gui", rpm:"synergy-gui~1.12.0~1.mga7", rls:"MAGEIA7"))) {
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
