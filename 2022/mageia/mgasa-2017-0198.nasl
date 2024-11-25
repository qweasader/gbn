# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2017.0198");
  script_cve_id("CVE-2017-6922");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-02-13 16:35:42 +0000 (Wed, 13 Feb 2019)");

  script_name("Mageia: Security Advisory (MGASA-2017-0198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2017-0198");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2017-0198.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21152");
  script_xref(name:"URL", value:"https://www.debian.org/security/2017/dsa-3897");
  script_xref(name:"URL", value:"https://www.drupal.org/SA-CORE-2017-003");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.53");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.54");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.55");
  script_xref(name:"URL", value:"https://www.drupal.org/project/drupal/releases/7.56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'drupal' package(s) announced via the MGASA-2017-0198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Greg Knaddison, Mori Sugimoto and iancawthorne discovered that files
uploaded by anonymous users into a private file system can be accessed
by other anonymous users leading to an access bypass vulnerability
(CVE-2017-6922).");

  script_tag(name:"affected", value:"'drupal' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"drupal", rpm:"drupal~7.56~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-mysql", rpm:"drupal-mysql~7.56~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-postgresql", rpm:"drupal-postgresql~7.56~1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"drupal-sqlite", rpm:"drupal-sqlite~7.56~1.mga5", rls:"MAGEIA5"))) {
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
