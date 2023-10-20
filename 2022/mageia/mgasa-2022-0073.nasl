# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0073");
  script_cve_id("CVE-2021-45444");
  script_tag(name:"creation_date", value:"2022-02-18 03:17:16 +0000 (Fri, 18 Feb 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-23 20:16:00 +0000 (Wed, 23 Feb 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0073)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0073");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0073.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30057");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/2P3LPMGENEHKDWFO4MWMZSZL6G7Y4CV7/");
  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5078");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh' package(s) announced via the MGASA-2022-0073 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"In zsh before 5.8.1, an attacker can achieve code execution if they control
a command output inside the prompt, as demonstrated by a %F argument. This
occurs because of recursive PROMPT_SUBST expansion. (CVE-2021-45444)");

  script_tag(name:"affected", value:"'zsh' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.8.1~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"zsh-doc", rpm:"zsh-doc~5.8.1~1.mga8", rls:"MAGEIA8"))) {
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
