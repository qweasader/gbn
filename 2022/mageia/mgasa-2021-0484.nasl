# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2021.0484");
  script_cve_id("CVE-2021-32760", "CVE-2021-41103");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-10-23T05:05:59+0000");
  script_tag(name:"last_modification", value:"2024-10-23 05:05:59 +0000 (Wed, 23 Oct 2024)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-14 19:38:38 +0000 (Thu, 14 Oct 2021)");

  script_name("Mageia: Security Advisory (MGASA-2021-0484)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2021-0484");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2021-0484.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=29268");
  script_xref(name:"URL", value:"https://github.com/containerd/containerd/security/advisories/GHSA-c2h3-6mxw-7mvq");
  script_xref(name:"URL", value:"https://github.com/containerd/containerd/security/advisories/GHSA-c72p-9xmj-rx3w");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/DDMNDPJJTP3J5GOEDB66F6MGXUTRG3Y3/");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/thread/M7ZZTABKTSJ5DYVDIQ7CVZG5HABGM2EC/");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KOVJMTDKAFMTONFNVO7Z327OFE52V7FK/");
  script_xref(name:"URL", value:"https://lists.suse.com/pipermail/sle-security-updates/2021-October/009566.html");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5012-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-5100-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker-containerd' package(s) announced via the MGASA-2021-0484 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A bug was found in containerd where pulling and extracting a
specially-crafted container image can result in Unix file permission
changes for existing files in the host's filesystem. Changes to file
permissions can deny access to the expected owner of the file, widen
access to others, or set extended bits like setuid, setgid, and sticky.
This bug does not directly allow files to be read, modified, or executed
without an additional cooperating process.");

  script_tag(name:"affected", value:"'docker-containerd' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker-containerd", rpm:"docker-containerd~1.5.7~1.mga8", rls:"MAGEIA8"))) {
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
