# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827903");
  script_version("2023-10-12T05:05:32+0000");
  script_cve_id("CVE-2022-41854");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2023-10-12 05:05:32 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-15 20:29:00 +0000 (Tue, 15 Nov 2022)");
  script_tag(name:"creation_date", value:"2023-07-08 01:09:56 +0000 (Sat, 08 Jul 2023)");
  script_name("Fedora: Security Advisory for picocli (FEDORA-2023-27ec59a486)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-27ec59a486");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/3DDXEXXWAZGF5AVHIPGFPXIWL6TSMKJE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'picocli'
  package(s) announced via the FEDORA-2023-27ec59a486 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Picocli is a modern library and framework, written in Java, that contains both
an annotations API and a programmatic API. It features usage help with ANSI
colors and styles, TAB auto-completion and nested sub-commands. In a single
file, so you can include it in source form. This lets users run picocli-based
applications without requiring picocli as an external dependency.");

  script_tag(name:"affected", value:"'picocli' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"picocli", rpm:"picocli~4.7.4~1.fc38", rls:"FC38"))) {
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