# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827813");
  script_version("2023-10-13T05:06:10+0000");
  script_cve_id("CVE-2022-39335");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2023-10-13 05:06:10 +0000 (Fri, 13 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-02 15:29:00 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-12 01:07:03 +0000 (Mon, 12 Jun 2023)");
  script_name("Fedora: Security Advisory for matrix-synapse (FEDORA-2023-eb65439ec0)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-eb65439ec0");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/T2MBNMZAFY4RCZL2VGBGAPKGB4JUPZVS");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'matrix-synapse'
  package(s) announced via the FEDORA-2023-eb65439ec0 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Matrix is an ambitious new ecosystem for open federated Instant Messaging and
VoIP. Synapse is a reference 'homeserver' implementation of Matrix from the
core development team, written in Python/Twisted. It is intended
to showcase the concept of Matrix and let folks see the spec in the context of
a coded base and let you run your own homeserver and generally help bootstrap
the ecosystem.");

  script_tag(name:"affected", value:"'matrix-synapse' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"matrix-synapse", rpm:"matrix-synapse~1.63.1~3.fc37", rls:"FC37"))) {
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
