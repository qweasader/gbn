# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827482");
  script_version("2023-04-19T10:19:33+0000");
  # TODO: No CVE assigned yet.
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-19 10:19:33 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-14 01:06:22 +0000 (Fri, 14 Apr 2023)");
  script_name("Fedora: Security Advisory for polkit (FEDORA-2023-4936e4e7f1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-4936e4e7f1");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/TIUNNQAVTSJNSIPZFJJWU46DXI44JUNE");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit'
  package(s) announced via the FEDORA-2023-4936e4e7f1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"polkit is a toolkit for defining and handling authorizations.  It is
used for allowing unprivileged processes to speak to privileged
processes.");

  script_tag(name:"affected", value:"'polkit' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"polkit", rpm:"polkit~121~4.fc37.2", rls:"FC37"))) {
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