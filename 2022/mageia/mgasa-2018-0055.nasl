# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2018.0055");
  script_cve_id("CVE-2017-8288");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-05-10 16:11:15 +0000 (Wed, 10 May 2017)");

  script_name("Mageia: Security Advisory (MGASA-2018-0055)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2018-0055");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2018-0055.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=21631");
  script_xref(name:"URL", value:"https://lists.opensuse.org/opensuse-updates/2017-08/msg00101.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gnome-shell' package(s) announced via the MGASA-2018-0055 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"gnome-shell through 3.24.1 mishandles extensions that fail to reload,
which can lead to leaving extensions enabled in the lock screen. With
these extensions, a bystander could launch applications (but not interact
with them), see information from the extensions (e.g., what applications
you have opened or what music you were playing), or even execute arbitrary
commands. It all depends on what extensions a user has enabled. The
problem is caused by lack of exception handling in
js/ui/extensionSystem.js (CVE-2017-8288).");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on Mageia 5.");

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

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell", rpm:"gnome-shell~3.14.3~8.3.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gnome-shell-docs", rpm:"gnome-shell-docs~3.14.3~8.3.mga5", rls:"MAGEIA5"))) {
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
