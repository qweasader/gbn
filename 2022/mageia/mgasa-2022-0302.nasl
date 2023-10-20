# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2022.0302");
  script_cve_id("CVE-2022-29154");
  script_tag(name:"creation_date", value:"2022-08-26 04:58:48 +0000 (Fri, 26 Aug 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-08-09 18:22:00 +0000 (Tue, 09 Aug 2022)");

  script_name("Mageia: Security Advisory (MGASA-2022-0302)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2022-0302");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2022-0302.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=30696");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2022/q3/77");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2022/08/02/1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OZDMOCCGHF4NPIRQFQC2LBFH6YXI6QMU/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the MGASA-2022-0302 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"An issue was discovered in rsync before 3.2.5 that allows malicious remote
servers to write arbitrary files inside the directories of connecting
peers. The server chooses which files/directories are sent to the client.
However, the rsync client performs insufficient validation of file names.
A malicious rsync server (or Man-in-The-Middle attacker) can overwrite
arbitrary files in the rsync client target directory and subdirectories
(for example, overwrite the .ssh/authorized_keys file). (CVE-2022-29154)");

  script_tag(name:"affected", value:"'rsync' package(s) on Mageia 8.");

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

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.2.2~2.1.mga8", rls:"MAGEIA8"))) {
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
