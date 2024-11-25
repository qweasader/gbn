# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0009");
  script_cve_id("CVE-2022-29153", "CVE-2022-36109", "CVE-2022-3920");
  script_tag(name:"creation_date", value:"2023-03-28 00:26:44 +0000 (Tue, 28 Mar 2023)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-11-18 20:21:33 +0000 (Fri, 18 Nov 2022)");

  script_name("Mageia: Security Advisory (MGASA-2023-0009)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0009");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0009.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30834");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/#201018");
  script_xref(name:"URL", value:"https://docs.docker.com/engine/release-notes/#201020");
  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-rc4r-wh2q-q6c4");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RBODKZL7HQE5XXS3SA2VIDVL4LAA5RWH/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/RQQ4E3JBXVR3VK5FIZVJ3QS2TAOOXXTQ/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/VFYXCTLOSESYIP72BUYD6ECDIMUM4WMB/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker' package(s) announced via the MGASA-2023-0009 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Server side request forgery (CVE-2022-29153)

Bypass primary group restrictions due to a flaw in the supplementary group
access setup (CVE-2022-36109)

Imported Nodes/Services Information leak in moby-engine. (CVE-2022-3920)");

  script_tag(name:"affected", value:"'docker' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~20.10.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~20.10.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~20.10.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-logrotate", rpm:"docker-logrotate~20.10.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-nano", rpm:"docker-nano~20.10.22~1.mga8", rls:"MAGEIA8"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~20.10.22~1.mga8", rls:"MAGEIA8"))) {
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
