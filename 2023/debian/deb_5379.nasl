# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5379");
  script_cve_id("CVE-2023-28686");
  script_tag(name:"creation_date", value:"2023-03-30 04:25:34 +0000 (Thu, 30 Mar 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-01 06:15:00 +0000 (Sat, 01 Apr 2023)");

  script_name("Debian: Security Advisory (DSA-5379)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5379");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5379");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5379");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/dino-im");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'dino-im' package(s) announced via the DSA-5379 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kim Alvefur discovered that insufficient message sender validation in dino-im, a modern XMPP/Jabber client, may result in manipulation of entries in the personal bookmark store without user interaction via a specially crafted message. Additionally an attacker can take advantage of this flaw to change how group chats are displayed or force a user to join or leave an attacker-selected groupchat.

For the stable distribution (bullseye), this problem has been fixed in version 0.2.0-3+deb11u1.

We recommend that you upgrade your dino-im packages.

For the detailed security status of dino-im please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'dino-im' package(s) on Debian 11.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"dino-im", ver:"0.2.0-3+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dino-im-common", ver:"0.2.0-3+deb11u1", rls:"DEB11"))) {
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
