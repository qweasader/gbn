# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2020.0483");
  script_cve_id("CVE-2020-12695", "CVE-2020-28926");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2023-06-20T05:05:24+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:24 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-04-23 00:15:00 +0000 (Fri, 23 Apr 2021)");

  script_name("Mageia: Security Advisory (MGASA-2020-0483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA7");

  script_xref(name:"Advisory-ID", value:"MGASA-2020-0483");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2020-0483.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=27755");
  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4806");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'minidlna' package(s) announced via the MGASA-2020-0483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that minidlna does not forbid the acceptance of a
subscription request with a delivery URL on a different network segment than
the fully qualified event-subscription URL, aka the CallStranger issue
(CVE-2020-12695).

Minidlna before versions 1.3.0 allows remote code execution. Sending a
malicious UPnP HTTP request to the miniDLNA service using HTTP chunked
encoding can lead to a signedness bug resulting in a buffer overflow in calls
to memcpy/memmove (CVE-2020-28926).");

  script_tag(name:"affected", value:"'minidlna' package(s) on Mageia 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"minidlna", rpm:"minidlna~1.2.1~3.1.mga7", rls:"MAGEIA7"))) {
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
