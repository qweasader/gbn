# SPDX-FileCopyrightText: 2022 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2016.0177");
  script_cve_id("CVE-2016-2054", "CVE-2016-2055", "CVE-2016-2056", "CVE-2016-2057", "CVE-2016-2058");
  script_tag(name:"creation_date", value:"2022-01-28 10:58:44 +0000 (Fri, 28 Jan 2022)");
  script_version("2024-02-02T05:06:09+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:09 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2016-04-14 13:33:01 +0000 (Thu, 14 Apr 2016)");

  script_name("Mageia: Security Advisory (MGASA-2016-0177)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA5");

  script_xref(name:"Advisory-ID", value:"MGASA-2016-0177");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2016-0177.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=17846");
  script_xref(name:"URL", value:"https://www.debian.org/security/2016/dsa-3495");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xymon' package(s) announced via the MGASA-2016-0177 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Updated xymon packages fix security vulnerabilities:


The incorrect handling of user-supplied input in the 'config' command can
trigger a stack-based buffer overflow, resulting in denial of service (via
application crash) or remote code execution (CVE-2016-2054).

The incorrect handling of user-supplied input in the 'config' command can
lead to an information leak by serving sensitive configuration files to a
remote user (CVE-2016-2055).

The commands handling password management do not properly validate
user-supplied input, and are thus vulnerable to shell command injection by a
remote user (CVE-2016-2056).

Incorrect permissions on an internal queuing system allow a user with a local
account on the xymon master server to bypass all network-based access control
lists, and thus inject messages directly into xymon (CVE-2016-2057).

Incorrect escaping of user-supplied input in status webpages can be used to
trigger reflected cross-site scripting attacks (CVE-2016-2058).

Note that to effectively fix CVE-2016-2055, the /etc/xymon/xymonpasswd
configuration file should be owned by user and group apache with 640
permissions.");

  script_tag(name:"affected", value:"'xymon' package(s) on Mageia 5.");

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

if(release == "MAGEIA5") {

  if(!isnull(res = isrpmvuln(pkg:"xymon", rpm:"xymon~4.3.17~5.1.mga5", rls:"MAGEIA5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"xymon-client", rpm:"xymon-client~4.3.17~5.1.mga5", rls:"MAGEIA5"))) {
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
