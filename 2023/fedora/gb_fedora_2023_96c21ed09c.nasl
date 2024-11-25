# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884979");
  script_version("2024-09-11T05:05:55+0000");
  script_cve_id("CVE-2023-45239");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2024-09-11 05:05:55 +0000 (Wed, 11 Sep 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-12 17:26:00 +0000 (Thu, 12 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-10-10 01:15:56 +0000 (Tue, 10 Oct 2023)");
  script_name("Fedora: Security Advisory for tacacs (FEDORA-2023-96c21ed09c)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-96c21ed09c");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/X4J7ZYMFZB4G4OU5EDJPQLP6F6RKDGIH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tacacs'
  package(s) announced via the FEDORA-2023-96c21ed09c advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tacacs+ (tac_plus) is a C daemon that authenticates requests via the Tacacs+
Protocol and logs accounting information.");


  script_tag(name:"affected", value:"'tacacs' package(s) on Fedora 39.");

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

  if(!isnull(res = isrpmvuln(pkg:"tacacs-F4.0.4.28.7fb~20231005g4fdf178", rpm:"tacacs-F4.0.4.28.7fb~20231005g4fdf178~1.fc39", rls:"FC39"))) {
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
