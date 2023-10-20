# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0108");
  script_cve_id("CVE-2016-9840", "CVE-2016-9841", "CVE-2016-9842", "CVE-2016-9843");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-27 16:40:00 +0000 (Mon, 27 Jun 2022)");

  script_name("Mageia: Security Advisory (MGASA-2020-0108)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0108");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0108.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=26254");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'rsync' package(s) announced via the MGASA-2020-0108 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated rsync packages fix security vulnerabilities:

It was discovered that rsync incorrectly handled pointer arithmetic in
zlib. An attacker could use this issue to cause rsync to crash, resulting
in a denial of service, or possibly execute arbitrary code (CVE-2016-9840,
CVE-2016-9841)

It was discovered that rsync incorrectly handled vectors involving left
shifts of negative integers in zlib. An attacker could use this issue to
cause rsync to crash, resulting in a denial of service, or possibly
execute arbitrary code (CVE-2016-9842).

It was discovered that rsync incorrectly handled vectors involving big-
endian CRC calculation in zlib. An attacker could use this issue to cause
rsync to crash, resulting in a denial of service, or possibly execute
arbitrary code (CVE-2016-9843).

Please note, we now compile against system zlib. If rsync fails to sync
with older remote systems using compression (-z), you have either update
the remote host to a newer version or disable compression.");

  script_tag(name:"affected", value:"'rsync' package(s) on Mageia 7.");

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

if(release == "MAGEIA7") {

  if(!isnull(res = isrpmvuln(pkg:"rsync", rpm:"rsync~3.1.3~4.mga7", rls:"MAGEIA7"))) {
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
